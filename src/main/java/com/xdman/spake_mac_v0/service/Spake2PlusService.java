package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyResponseTlv;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
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
public class Spake2PlusService {
  private final SecureRandom secureRandom = new SecureRandom();
  private final ECParameterSpec ecParams = ECNamedCurveTable.getParameterSpec("secp256r1"); // NIST P-256
  private final BigInteger n = ecParams.getN(); // Order of base point G
  private final ECPoint G = ecParams.getG(); // Base point

  private static final int DEFAULT_SCRYPT_COST = 4096;  // Nscrypt
  private static final int DEFAULT_BLOCK_SIZE = 8;       // r
  private static final int DEFAULT_PARALLELIZATION = 1;  // p
  private static final byte[] DEFAULT_VOD_FW_VERSIONS = new byte[] {0x01, 0x00};  // v1.0
  private static final byte[] DEFAULT_DK_PROTOCOL_VERSIONS = new byte[] {0x01, 0x00};  // v1.0

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
  public Spake2PlusRequestCommandTlv createSpake2PlusRequest(String salt) {

	// Store password as bytes
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
	return request;
  }

  /**
   * Process SPAKE2+ request and generate response
   * Based on Listing 18-3: Device-side Public Point Generation
   */
  public Spake2PlusRequestResponseTlv processSpake2PlusRequest(Spake2PlusRequestCommandTlv request, String password) {

	// Generate Scrypt output (based on Listing 18-1)
	byte[] pwd = HexUtil.parseHex(password);
	byte[] cryptographicSalt = HexUtil.parseHex(request.getCryptographicSalt());
	byte[] z = SCrypt.generate(pwd, cryptographicSalt, DEFAULT_SCRYPT_COST, DEFAULT_BLOCK_SIZE, DEFAULT_PARALLELIZATION, 80);

	// Split z into z0 and z1 (40 bytes each)
	byte[] z0 = Arrays.copyOfRange(z, 0, 40);
	byte[] z1 = Arrays.copyOfRange(z, 40, 80);

	// Convert to w0 and w1 scalars (mod n-1) + 1
	BigInteger z0BigInt = new BigInteger(1, z0);
	BigInteger z1BigInt = new BigInteger(1, z1);
	BigInteger w0 = z0BigInt.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);;
	BigInteger w1 = z1BigInt.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);

	// Compute L = w1 * G
	ECPoint L = G.multiply(w1);
	// Generate random scalar x on chosen curve
	BigInteger x = new BigInteger(256, secureRandom).mod(n);
	// Calculate X = x*G + w0*M
	ECPoint X = G.multiply(x).add(M.multiply(w0));;

	// Create response TLV
	Spake2PlusRequestResponseTlv response = new Spake2PlusRequestResponseTlv();
	response.setCurvePointX(X.getEncoded(false)); // Include 0x04 prefix

	// Optional: Select supported version
	response.setSelectedVodFwVersion(new byte[]{0x01, 0x00});
	return response;
  }

  /**
   * Process SPAKE2+ response and generate verify request
   * Based on Listing 18-2: Vehicle-side Public Point Generation
   * and Listing 18-4: Vehicle-side Computation of Shared Secret
   * and Listing 18-6: Derivation of Evidence Keys
   * and Listing 18-7: Vehicle-side Computation of Evidence
   */
  public Spake2PlusVerifyCommandTlv processSpake2PlusResponse(Spake2PlusRequestResponseTlv response) {

	// Parse X from response
	ECPoint receivedX = ecParams.getCurve().decodePoint(response.getCurvePointX());

	// Generate random scalar y (Vehicle-side)
	BigInteger y = new BigInteger(256, secureRandom).mod(n);

	// Calculate Y = y*G + w0*N
	ECPoint Y = G.multiply(y).add(N.multiply(w0));

	// Calculate Z = y*(X - w0*M)
	ECPoint Z = receivedX.subtract(M.multiply(w0)).multiply(y);

	// Calculate V = y*L
	ECPoint V = L.multiply(y);

	// Calculate K = SHA-256(len(X) || X || len(Y) || Y || len(Z) || Z || len(V) || V || len(w0) || w0)
	byte[] K = computeK(receivedX, Y, Z, V);

	// Split K into CK and SK
	this.CK = Arrays.copyOfRange(K, 0, 16); // First 128 bits
	this.SK = Arrays.copyOfRange(K, 16, 32); // Next 128 bits

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
   * Process SPAKE2+ verify request and generate verify response
   * Based on Listing 18-5: Device-side Computation of Shared Secret
   * and Listing 18-6: Derivation of Evidence Keys
   * and Listing 18-8: Device-side Computation of Evidence
   * and Listing 18-9: Derivation of System Keys
   */
  public Spake2PlusVerifyResponseTlv processSpake2PlusVerifyRequest(Spake2PlusVerifyCommandTlv request) {

	// Parse Y from request
	ECPoint Y = ecParams.getCurve().decodePoint(request.getCurvePointY());

	// Calculate Z = x*(Y - w0*N)
	ECPoint Z = Y.subtract(N.multiply(w0)).multiply(x);

	// Calculate V = w1*(Y - w0*N)
	ECPoint V = Y.subtract(N.multiply(w0)).multiply(w1);

	// Calculate K = SHA-256(len(X) || X || len(Y) || Y || len(Z) || Z || len(V) || V || len(w0) || w0)
	byte[] K = computeK(X, Y, Z, V);

	// Split K into CK and SK
	this.CK = Arrays.copyOfRange(K, 0, 16); // First 128 bits
	this.SK = Arrays.copyOfRange(K, 16, 32); // Next 128 bits

	// Derive evidence keys K1, K2
	byte[] evidenceKeys = deriveEvidenceKeys(CK);
	byte[] K1 = Arrays.copyOfRange(evidenceKeys, 0, 16);
	byte[] K2 = Arrays.copyOfRange(evidenceKeys, 16, 32);

	// Verify vehicle evidence
	byte[] expectedVehicleEvidence = computeCMAC(K1, Y.getEncoded(false));
	if (!Arrays.equals(expectedVehicleEvidence, request.getVehicleEvidence())) {
	  throw new SecurityException("Vehicle evidence verification failed");
	}

	// Compute device evidence
	byte[] deviceEvidence = computeCMAC(K2, X.getEncoded(false));

	// Derive system keys
	boolean supportExtendedKeys = false; // Set based on your requirements
	byte[] systemKeys = deriveSystemKeys(SK, supportExtendedKeys);

	byte[] Kenc = Arrays.copyOfRange(systemKeys, 0, 16);
	byte[] Kmac = Arrays.copyOfRange(systemKeys, 16, 32);
	byte[] Krmac = Arrays.copyOfRange(systemKeys, 32, 48);
	byte[] longTermSharedSecret = Arrays.copyOfRange(systemKeys, 48, 64);

	// If extended keys are supported, extract them
	byte[] Kble_intro = null;
	byte[] Kble_oob_master = null;
	if (supportExtendedKeys && systemKeys.length >= 80) {
	  Kble_intro = Arrays.copyOfRange(systemKeys, 64, 80);
	  Kble_oob_master = Arrays.copyOfRange(systemKeys, 80, 96);
	}

	// Create verify response TLV
	Spake2PlusVerifyResponseTlv verifyResponse = new Spake2PlusVerifyResponseTlv();
	verifyResponse.setDeviceEvidence(deviceEvidence);

	return verifyResponse;
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
  private byte[] computeK(ECPoint X, ECPoint Y, ECPoint Z, ECPoint V) {
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
   * Derives system keys based on Listing 18-9
   */
  private byte[] deriveSystemKeys(byte[] SK, boolean extendedKeysSupport) {
	try {
	  // HKDF implementation (RFC5869)
	  // Note: This is a simplified version
	  MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

	  // Extract
	  byte[] prk = hmacSha256(null, SK);

	  // Info string preparation
	  byte[] info = "SystemKeys".getBytes();

	  // Expand
	  int okmLength = extendedKeysSupport ? 96 : 64; // With or without extended keys
	  byte[] okm = new byte[okmLength];
	  byte[] t = new byte[0];

	  for (int i = 1; i <= Math.ceil(okmLength * 1.0 / sha256.getDigestLength()); i++) {
		byte[] input = new byte[t.length + info.length + 1];
		System.arraycopy(t, 0, input, 0, t.length);
		System.arraycopy(info, 0, input, t.length, info.length);
		input[input.length - 1] = (byte) i;

		t = hmacSha256(prk, input);

		int copyLength = Math.min(t.length, okm.length - (i - 1) * sha256.getDigestLength());
		System.arraycopy(t, 0, okm, (i - 1) * sha256.getDigestLength(), copyLength);
	  }

	  return okm;
	} catch (Exception e) {
	  throw new RuntimeException("Error deriving system keys", e);
	}
  }

  /**
   * Computes CMAC for evidence based on Listing 18-7/18-8
   */
  private byte[] computeCMAC(byte[] key, byte[] data) {
	try {
	  // CMAC-AES-128 as defined in RFC4493
	  Mac mac = Mac.getInstance("AESCMAC");
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