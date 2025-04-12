package com.xdman.spake_mac_v0.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xdman.spake_mac_v0.model.DeviceRequestCommandResponse;
import com.xdman.spake_mac_v0.model.DeviceVerifyCommandRequest;
import com.xdman.spake_mac_v0.model.Spake2PlusResponseWrapper;
import com.xdman.spake_mac_v0.model.VehicleRequestCommandRequest;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.VehicleVerifyCommandRequest;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.service.Spake2PlusVehicleService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class Spake2PlusVehicleControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private Spake2PlusVehicleService spake2PlusVehicleService;

    private Spake2PlusRequestCommandTlv mockRequest;
    private Spake2PlusVerifyCommandTlv mockVerify;

    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";
    private static final String VERIFY_COMMAND_TLV = "8032000055524104946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF225710CBEC779FF69B8BBED4CBE5FA4A81181B00";
    private static final String REQUEST_RESPONSE_TLV = "504104F6C30CA94ED2B6C25A979458BE967458353AA08898C7E763846ED2DFC50F2D58BC76F296DB1743C648ED1207404F925E80F366FB6FF75253502FC6F5C64BF71D9000";
    private static final String VERIFY_RESPONSE_TLV = "5810B169C1D2F8858E659474D2F8858E65949000";

    @BeforeEach
    public void setup() {
        mockRequest = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        mockVerify = new Spake2PlusVerifyCommandTlv().decode(VERIFY_COMMAND_TLV);
    }

    @Test
    public void testProcessRequest_ValidResponse() throws Exception {
        Spake2PlusRequestWrapper wrapper = new Spake2PlusRequestWrapper(mockRequest, null);
        when(spake2PlusVehicleService.generateSpake2PlusRequest(any(String.class), any(String.class)))
                .thenReturn(wrapper);

        VehicleRequestCommandRequest request = new VehicleRequestCommandRequest("password123", "salt123");
        ResultActions response = mockMvc.perform(post("/api/spake2plus/vehicle/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        response.andExpect(status().isOk())
          .andExpect(jsonPath("$.message").value(mockRequest.encode()));
    }

    @Test
    public void testProcessVerify_ValidResponse() throws Exception {
        Spake2PlusVerifyCommandTlv verifyCommandTlv = new Spake2PlusVerifyCommandTlv().decode(VERIFY_COMMAND_TLV);
        when(spake2PlusVehicleService.createSpake2PlusVerifyRequest(any(Spake2PlusRequestResponseTlv.class)))
          .thenReturn(verifyCommandTlv);

        VehicleVerifyCommandRequest request = new VehicleVerifyCommandRequest(REQUEST_RESPONSE_TLV);
        ResultActions response = mockMvc.perform(post("/api/spake2plus/vehicle/verify")
          .contentType(MediaType.APPLICATION_JSON)
          .content(objectMapper.writeValueAsString(request)));

        response.andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value(mockVerify.encode()));



    }
}