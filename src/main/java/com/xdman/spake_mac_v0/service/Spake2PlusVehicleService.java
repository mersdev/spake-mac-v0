package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.domain.Spake2PlusVehicleData;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.repository.Spake2PlusVehicleRepo;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
@Slf4j
public class Spake2PlusVehicleService {
  private final SecureRandom secureRandom = new SecureRandom();
  private final ECParameterSpec ecParams = ECNamedCurveTable.getParameterSpec("secp256r1"); // NIST P-256
  private final BigInteger n = ecParams.getN(); // Order of base point G
  private final ECPoint G = ecParams.getG(); // Base point

  private static final int DEFAULT_SCRYPT_COST = 4096;  // Nscrypt
  private static final int DEFAULT_BLOCK_SIZE = 8;       // r
  private static final int DEFAULT_PARALLELIZATION = 1;  // p
  private static final byte[] DEFAULT_VOD_FW_VERSIONS = new byte[] {0x01, 0x00};  // v1.0
  private static final byte[] DEFAULT_DK_PROTOCOL_VERSIONS = new byte[] {0x01, 0x00};  // v1.0

  @Autowired
  private Spake2PlusVehicleRepo spake2PlusVehicleRepo;

  // Protocol points - Fix the point coordinates
  private static final ECPoint M = validatePoint(
	"04" +
	  "886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB95AFD497333D8FA12F" +
	  "5FF355163E43CE224E0B0E65FF02AC8E5C7BE09419C785E0CA547D55A12E2D20",
	"M"
  );

  private static final ECPoint N = validatePoint(
	"04" +
	  "D8BBD6C639C62937B04D997F38C3770719C629D7014D49A24B4F98BAA1292B49" +
	  "07D60AA6BFADE45008A636337F5168C64D9BD36034808CD564490B1E656EDBE7",
	"N"
  );

  /**
   * Creates a SPAKE2+ request with all necessary parameters
   * Based on Listing 18-1: Server Password Generation
   */
  public Spake2PlusRequestWrapper createSpake2PlusRequest(String password, String salt, String requestId) {

	// Store password as bytes// Generate Scrypt output (based on Listing 18-1)
	byte[] pwd = HexUtil.parseHex(password);
	byte[] cryptographicSalt = HexUtil.parseHex(salt);

	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	try {
	  outputStream.write(cryptographicSalt);
	  outputStream.write(ByteBuffer.allocate(4).putInt(DEFAULT_SCRYPT_COST).array());
	  outputStream.write(ByteBuffer.allocate(2).putShort((short) DEFAULT_BLOCK_SIZE).array());
	  outputStream.write(ByteBuffer.allocate(2).putShort((short) DEFAULT_PARALLELIZATION).array());
	} catch (IOException e) {
	  throw new IllegalArgumentException("Failed to combine Scrypt parameters", e);
	}

	byte[] z = SCrypt.generate(pwd, cryptographicSalt, DEFAULT_SCRYPT_COST, DEFAULT_BLOCK_SIZE, DEFAULT_PARALLELIZATION, 80);

	// Split z into z0 and z1 (40 bytes each)
	byte[] z0 = Arrays.copyOfRange(z, 0, 40);
	byte[] z1 = Arrays.copyOfRange(z, 40, 80);

	// Convert to w0 and w1 scalars (mod n-1) + 1
	BigInteger z0BigInt = new BigInteger(1, z0);
	BigInteger z1BigInt = new BigInteger(1, z1);
	BigInteger w0 = z0BigInt.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);;
	BigInteger w1 = z1BigInt.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);

	Spake2PlusVehicleData configurations = new Spake2PlusVehicleData();
	configurations.apply(config -> {
	  config.setW0(w0);
	  config.setW1(w1);
	  config.setRequestId(requestId);
	});

	spake2PlusVehicleRepo.save(configurations);

	// Create the request TLV
	Spake2PlusRequestCommandTlv request = new Spake2PlusRequestCommandTlv();
	request.setScryptConfig(outputStream.toByteArray());
	request.setCryptographicSalt(salt);
	request.setScryptCost(DEFAULT_SCRYPT_COST);
	request.setBlockSize(DEFAULT_BLOCK_SIZE);
	request.setParallelization(DEFAULT_PARALLELIZATION);
	request.setVodFwVersions(DEFAULT_VOD_FW_VERSIONS); // Example version
	request.setDkProtocolVersions(DEFAULT_DK_PROTOCOL_VERSIONS); // Example version
	request.setBtVersions(new byte[]{0x05, 0x00}); // Example version
	request.setVehicleBrand(HexUtil.toHexString(new byte[]{0x00, 0x03})); // Example brand code

	return new Spake2PlusRequestWrapper(request, configurations);
  }

  /**
   * Process SPAKE2+ response and generate verify request
   * Based on Listing 18-2: Vehicle-side Public Point Generation
   * and Listing 18-4: Vehicle-side Computation of Shared Secret
   * and Listing 18-6: Derivation of Evidence Keys
   * and Listing 18-7: Vehicle-side Computation of Evidence
   */
  public Spake2PlusVerifyCommandTlv processSpake2PlusResponse(Spake2PlusRequestResponseTlv response, Spake2PlusVehicleData config) {

	BigInteger w0 = config.getW0();
	BigInteger w1 = config.getW1();
	// Parse X from response
	ECPoint receivedX = ecParams.getCurve().decodePoint(response.getCurvePointX());

	log.info("w0: {}, w1: {}", w0, w1);

	// Compute L = w1 * G
	ECPoint L = G.multiply(w1);

	// Generate random scalar y (Vehicle-side)
	BigInteger y = new BigInteger(256, secureRandom).mod(n);

	// Calculate Y = y*G + w0*N
	ECPoint Y = G.multiply(y).add(N.multiply(w0));

	// Calculate Z = y*(X - w0*M)
	ECPoint Z = receivedX.subtract(M.multiply(w0)).multiply(y);

	// Calculate V = y*L
	ECPoint V = L.multiply(y);

	// Calculate K = SHA-256(len(X) || X || len(Y) || Y || len(Z) || Z || len(V) || V || len(w0) || w0)
	byte[] K = computeK(w0, receivedX, Y, Z, V);

	// Split K into CK and SK
	byte[] CK = Arrays.copyOfRange(K, 0, 16); // First 128 bits
	byte[] SK = Arrays.copyOfRange(K, 16, 32); // Next 128 bits

	// Derive evidence keys K1, K2
	byte[] evidenceKeys = deriveEvidenceKeys(CK);
	byte[] K1 = Arrays.copyOfRange(evidenceKeys, 0, 16);
	byte[] K2 = Arrays.copyOfRange(evidenceKeys, 16, 32);

	// Compute vehicle evidence
	byte[] vehicleEvidence = computeCMAC(K1, Y.getEncoded(false));

	// Create verify command TLV
	Spake2PlusVerifyCommandTlv verifyCommand = new Spake2PlusVerifyCommandTlv();
	verifyCommand.setCurvePointY(Y.getEncoded(false));
	verifyCommand.setVehicleEvidence(vehicleEvidence);

	return verifyCommand;
  }


  /**
   * Validates an EC point from its hex representation
   */
  private static ECPoint validatePoint(String hexPoint, String pointName) {
	try {
	  ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
	  ECCurve curve = params.getCurve();

	  byte[] pointBytes = HexUtil.parseHex(hexPoint);
	  ECPoint point = curve.decodePoint(pointBytes);

	  if (!point.isValid()) {
		throw new IllegalArgumentException("Invalid point: " + pointName);
	  }

	  return point;
	} catch (Exception e) {
	  throw new RuntimeException("Error validating point " + pointName, e);
	}
  }

  /**
   * Computes K value based on Listing 18-4/18-5
   */
  private byte[] computeK(BigInteger w0, ECPoint X, ECPoint Y, ECPoint Z, ECPoint V) {
	try {
	  MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

	  byte[] xBytes = X.getEncoded(false);
	  byte[] yBytes = Y.getEncoded(false);
	  byte[] zBytes = Z.getEncoded(false);
	  byte[] vBytes = V.getEncoded(false);
	  byte[] w0Bytes = w0.toByteArray();

	  // Add length prefixes (8-byte little-endian)
	  ByteBuffer buffer = ByteBuffer.allocate(
		8 + xBytes.length + 8 + yBytes.length +
		  8 + zBytes.length + 8 + vBytes.length +
		  8 + w0Bytes.length
	  );

	  buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN);

	  buffer.putLong(xBytes.length);
	  buffer.put(xBytes);

	  buffer.putLong(yBytes.length);
	  buffer.put(yBytes);

	  buffer.putLong(zBytes.length);
	  buffer.put(zBytes);

	  buffer.putLong(vBytes.length);
	  buffer.put(vBytes);

	  buffer.putLong(w0Bytes.length);
	  buffer.put(w0Bytes);

	  return sha256.digest(buffer.array());
	} catch (Exception e) {
	  throw new RuntimeException("Error computing K", e);
	}
  }

  /**
   * Derives evidence keys based on Listing 18-6
   */
  private byte[] deriveEvidenceKeys(byte[] CK) {
	try {
	  // HKDF implementation (RFC5869)
	  // Note: This is a simplified version
	  MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

	  // Extract
	  byte[] prk = hmacSha256(null, CK);

	  // Info string preparation
	  byte[] info = "ConfirmationKeys".getBytes();
	  byte[] tlv5B = new byte[]{0x5B, 0x01, 0x00}; // Example TLV
	  byte[] tlv5C = new byte[]{0x5C, 0x01, 0x01}; // Example TLV

	  byte[] infoBytes = new byte[info.length + tlv5B.length + tlv5C.length];
	  System.arraycopy(info, 0, infoBytes, 0, info.length);
	  System.arraycopy(tlv5B, 0, infoBytes, info.length, tlv5B.length);
	  System.arraycopy(tlv5C, 0, infoBytes, info.length + tlv5B.length, tlv5C.length);

	  // Expand
	  byte[] okm = new byte[32]; // K1 + K2 = 32 bytes
	  byte[] t = new byte[0];

	  for (int i = 1; i <= Math.ceil(32.0 / sha256.getDigestLength()); i++) {
		byte[] input = new byte[t.length + infoBytes.length + 1];
		System.arraycopy(t, 0, input, 0, t.length);
		System.arraycopy(infoBytes, 0, input, t.length, infoBytes.length);
		input[input.length - 1] = (byte) i;

		t = hmacSha256(prk, input);

		int copyLength = Math.min(t.length, okm.length - (i - 1) * sha256.getDigestLength());
		System.arraycopy(t, 0, okm, (i - 1) * sha256.getDigestLength(), copyLength);
	  }

	  return okm;
	} catch (Exception e) {
	  throw new RuntimeException("Error deriving evidence keys", e);
	}
  }


  /**
   * Computes CMAC for evidence based on Listing 18-7/18-8
   */
  private byte[] computeCMAC(byte[] key, byte[] data) {
	try {
	  // CMAC-AES-128 as defined in RFC4493
	  Mac mac = Mac.getInstance("AESCMAC", new BouncyCastleProvider());
	  SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	  mac.init(keySpec);
	  return mac.doFinal(data);
	} catch (Exception e) {
	  throw new RuntimeException("Error computing CMAC", e);
	}
  }

  /**
   * HMAC-SHA256 implementation for HKDF
   */
  private byte[] hmacSha256(byte[] key, byte[] data) {
	try {
	  Mac mac = Mac.getInstance("HmacSHA256");
	  if (key == null) {
		key = new byte[mac.getMacLength()];
	  }

	  SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
	  mac.init(keySpec);
	  return mac.doFinal(data);
	} catch (Exception e) {
	  throw new RuntimeException("Error in HMAC-SHA256", e);
	}
  }
}