# Ensemble local TreeSHAP findings

Mean signed per-booster class-margin contributions explain Tier 2, not RedRVFL or ensemble probability.

- SOCL5-14 / 2026-03-18: IT_SABOTAGE; level__file_delete_count +3.8398; level__http_request_count -0.2138; level__protected_file_touch_count +0.1183; level__external_connection_count -0.1077; if_device_file +0.0964

- SOCL5-14 / 2026-03-25: IT_SABOTAGE; level__file_delete_count +3.6577; level__protected_file_touch_count -0.4492; level__http_request_count -0.2138; level__external_connection_count -0.1077; if_device_file +0.0964

- SOCL5-14 / 2026-03-27: IT_SABOTAGE; level__file_delete_count +3.8909; level__protected_file_touch_count -0.4492; level__http_request_count -0.2138; level__external_connection_count -0.1077; if_device_file +0.0702

- SOCL8-23 / 2026-03-21: IT_SABOTAGE; level__file_delete_count +4.0895; level__protected_file_touch_count +0.6799; level__http_request_count +0.1213; if_device_file +0.1097; level__external_connection_count +0.0437

- SOCL8-23 / 2026-03-22: IT_SABOTAGE; level__file_delete_count +4.0928; level__protected_file_touch_count +0.6799; level__http_request_count +0.1213; if_device_file +0.1055; level__external_connection_count +0.0437

- SOCL8-23 / 2026-03-23: IT_SABOTAGE; level__file_delete_count +4.0038; level__protected_file_touch_count +0.6619; if_device_file +0.1030; level__http_request_count -0.1011; level__external_connection_count -0.0292

- DESKTOP-ST584BE / 2026-03-21: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.6715; level__usb_connect_count +0.9185; level__http_request_count +0.6735; level__file_access_count +0.6412; level__clipboard_copy_count +0.1892

- DESKTOP-ST584BE / 2026-03-22: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.6993; level__usb_connect_count +0.9067; level__http_request_count +0.6739; level__file_access_count +0.6295; level__clipboard_copy_count +0.1940

- DESKTOP-ST584BE / 2026-03-23: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.6047; level__usb_connect_count +0.9327; level__file_access_count +0.7077; if_device_file +0.2509; level__clipboard_copy_count +0.1704

- SOCL8-12 / 2026-03-22: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +3.1888; level__clipboard_copy_count +0.8459; level__http_request_count +0.4020; level__bytes_sent +0.2775; if_web_network +0.1437

- SOCL8-12 / 2026-03-24: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +3.3862; level__http_request_count +0.3009; level__clipboard_copy_count -0.2691; level__bytes_sent +0.2152; level__file_access_count -0.1743

- SOCL8-12 / 2026-03-23: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +3.3106; level__clipboard_copy_count -0.4253; level__file_access_count -0.3374; level__http_request_count +0.2745; level__bytes_sent +0.1954

- SOCL11-33 / 2026-03-24: IT_SABOTAGE; level__file_delete_count +3.6577; level__protected_file_touch_count -0.4492; level__http_request_count -0.2138; level__external_connection_count -0.1077; if_device_file +0.0702

- SOCL11-33 / 2026-03-18: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.5407; level__http_request_count -0.5665; level__file_access_count +0.5063; level__usb_connect_count +0.4849; if_device_file +0.3014

- SOCL11-33 / 2026-03-26: BENIGN; if_weighted_risk -0.4366; if_device_file -0.3612; level__named_pipe_event_count +0.3324; level__file_access_count -0.3091; level__http_request_count +0.2239

- SOCL5A-25 / 2026-03-26: CREDENTIAL_DUMP; level__lsass_handle_request_count +2.3039; level__failed_logons +1.2810; level__named_pipe_event_count -0.8948; if_execution +0.0876; level__admin_process_count -0.0410

- SOCL5A-25 / 2026-03-18: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.6413; level__http_request_count -0.5841; level__file_access_count +0.5141; level__usb_connect_count +0.3932; level__clipboard_copy_count -0.2584

- SOCL5A-25 / 2026-03-24: BENIGN; if_weighted_risk -0.4338; level__named_pipe_event_count +0.3986; if_device_file -0.3493; level__file_access_count -0.2654; level__http_request_count +0.2223

- SOCL11-18 / 2026-03-23: CREDENTIAL_DUMP; level__lsass_handle_request_count +2.9798; level__failed_logons +1.2725; if_execution +0.1962; past7_risk_mean -0.0523; level__named_pipe_event_count +0.0415

- SOCL11-18 / 2026-03-24: CREDENTIAL_DUMP; level__lsass_handle_request_count +2.9738; level__failed_logons +1.2516; if_execution +0.1985; level__named_pipe_event_count +0.0566; level__admin_process_count -0.0480

- SOCL11-18 / 2026-03-30: BENIGN; level__named_pipe_event_count +0.6470; if_weighted_risk -0.6392; level__http_request_count -0.2529; level__file_access_count -0.1953; level__lsass_handle_request_count -0.1550

- PHYSICS-SIR / 2026-03-27: IT_SABOTAGE; level__file_delete_count +3.6577; level__protected_file_touch_count -0.4492; level__http_request_count -0.2127; level__external_connection_count -0.1077; if_device_file +0.0659

- PHYSICS-SIR / 2026-03-23: BENIGN; if_weighted_risk -0.5344; level__named_pipe_event_count +0.2552; level__file_access_count -0.2467; level__failed_logons -0.2159; level__http_request_count +0.1758

- PHYSICS-SIR / 2026-03-18: BENIGN; if_weighted_risk -0.5235; level__named_pipe_event_count +0.4578; level__file_access_count -0.2761; level__http_request_count +0.2006; risk_minus_past7_mean -0.1506

- SOCL8-16 / 2026-03-25: IT_SABOTAGE; level__file_delete_count +3.8398; level__protected_file_touch_count -0.4492; level__http_request_count -0.2138; level__external_connection_count -0.1077; if_device_file +0.0702

- SOCL8-16 / 2026-03-30: BENIGN; if_weighted_risk -0.4399; level__named_pipe_event_count +0.4243; if_device_file -0.4074; level__file_access_count -0.2798; level__http_request_count +0.2186

- SOCL8-16 / 2026-03-23: BENIGN; if_weighted_risk -0.5636; level__named_pipe_event_count +0.4872; level__file_access_count -0.2586; level__http_request_count +0.1791; level__mean_process_count +0.1261

- SOCL8-02 / 2026-03-30: CREDENTIAL_DUMP; level__lsass_handle_request_count +2.9237; level__failed_logons +1.2756; if_execution +0.1933; level__named_pipe_event_count -0.1687; level__admin_process_count +0.0364

- SOCL8-02 / 2026-03-29: CREDENTIAL_DUMP; level__lsass_handle_request_count +2.6815; level__failed_logons -0.7432; level__named_pipe_event_count +0.7401; if_execution +0.3012; past7_risk_mean -0.0582

- SOCL8-02 / 2026-03-31: BENIGN; if_weighted_risk -0.5699; level__named_pipe_event_count +0.5614; level__lsass_handle_request_count -0.1398; risk_minus_past7_mean -0.1325; level__http_request_count +0.1201

- SOCL5A-30 / 2026-03-18: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.2705; level__usb_connect_count +0.8172; level__file_access_count +0.5808; level__http_request_count -0.5517; level__clipboard_copy_count -0.2650

- SOCL5A-30 / 2026-03-31: BENIGN; if_weighted_risk -0.5866; if_device_file -0.3917; level__named_pipe_event_count +0.3454; level__file_access_count -0.2537; level__http_request_count +0.1984

- SOCL5A-30 / 2026-03-19: BENIGN; if_weighted_risk -0.4137; level__named_pipe_event_count +0.3420; level__file_access_count -0.2587; level__http_request_count +0.2246; level__file_sharing_visit_count -0.1307

- SOCL9-21 / 2026-03-20: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.2121; level__usb_connect_count +0.6840; level__file_access_count +0.6334; level__http_request_count -0.5744; level__clipboard_copy_count -0.2764

- SOCL9-21 / 2026-03-18: BENIGN; if_weighted_risk -0.7520; if_device_file -0.3728; level__file_access_count -0.1931; risk_minus_past7_mean -0.1832; level__named_pipe_event_count -0.1762

- SOCL9-21 / 2026-03-31: BENIGN; level__named_pipe_event_count +0.5858; level__http_request_count -0.2648; level__file_access_count -0.1876; level__lsass_handle_request_count -0.1830; risk_minus_past7_mean -0.1140

- SOCL8-44 / 2026-03-31: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +3.0933; level__clipboard_copy_count -1.1468; level__http_request_count +0.2801; level__bytes_sent +0.1361; if_web_network +0.0906

- SOCL8-44 / 2026-03-25: BENIGN; if_weighted_risk -0.7583; level__named_pipe_event_count +0.3159; risk_minus_past7_mean -0.1926; level__file_access_count -0.1450; level__http_request_count +0.1159

- SOCL8-44 / 2026-03-19: BENIGN; if_weighted_risk -0.5416; level__file_access_count -0.3152; level__http_request_count +0.1760; level__named_pipe_event_count -0.1600; risk_minus_past7_mean -0.1348

- SOCL8-55 / 2026-03-26: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.3478; level__usb_connect_count +1.0050; level__file_access_count +0.6687; level__http_request_count +0.3145; if_device_file +0.2250

- SOCL8-55 / 2026-03-24: BENIGN; level__named_pipe_event_count +0.5438; if_weighted_risk -0.4628; past7_risk_std +0.1996; level__file_access_count -0.1346; risk_minus_past7_mean -0.1286

- SOCL8-55 / 2026-03-25: BENIGN; level__file_access_count -0.5359; if_weighted_risk +0.4100; level__file_access_entropy -0.1350; risk_minus_past7_mean +0.1245; level__named_pipe_event_count -0.0650

- SOCL8-08 / 2026-03-22: CREDENTIAL_DUMP; level__lsass_handle_request_count +1.4712; level__named_pipe_event_count +0.5397; level__failed_logons +0.3354; if_execution -0.2111; past7_risk_mean +0.0257

- SOCL8-08 / 2026-03-18: BENIGN; if_weighted_risk -0.4897; level__file_access_count -0.2762; level__http_request_count +0.2011; level__external_connection_count +0.1899; level__file_sharing_visit_count -0.1807

- SOCL8-08 / 2026-03-19: BENIGN; if_weighted_risk -0.6798; risk_minus_past7_mean -0.1745; level__file_access_count -0.1523; level__http_request_count +0.1352; level__mean_process_count +0.0701

- SOCL11-14 / 2026-03-17: DATA_HOARDING; level__clipboard_copy_count +2.2928; level__file_access_count +0.4121; level__http_request_count -0.3915; if_weighted_risk -0.1261; level__bytes_received -0.0953

- SOCL11-14 / 2026-03-20: BENIGN; level__lsass_handle_request_count -0.4159; level__file_access_count +0.2284; level__file_access_entropy +0.2083; level__mean_process_count +0.1482; risk_minus_past7_mean -0.1366

- SOCL11-14 / 2026-03-23: BENIGN; level__named_pipe_event_count +0.6302; if_weighted_risk -0.5311; level__lsass_handle_request_count -0.1584; level__mean_process_count +0.1407; level__http_request_count +0.1327

- MCALAB1-05 / 2026-03-30: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +2.9100; level__clipboard_copy_count -1.1573; level__http_request_count +0.3125; level__file_access_count +0.2783; level__bytes_sent +0.2176

- MCALAB1-05 / 2026-03-29: BENIGN; level__file_access_count +0.9822; level__named_pipe_event_count +0.5042; level__file_access_entropy +0.4495; level__http_request_count -0.4294; if_weighted_risk -0.3570

- MCALAB1-05 / 2026-03-17: BENIGN; level__http_request_count -0.6705; if_weighted_risk +0.5042; level__file_access_count +0.4903; level__named_pipe_event_count -0.1643; risk_minus_past7_mean +0.1129

- DESKTOP-F768FB6 / 2026-03-23: CLOUD_EXFILTRATION_PRECURSOR; level__file_sharing_visit_count +1.8994; level__clipboard_copy_count +1.0680; level__http_request_count +0.2680; level__bytes_sent +0.2492; level__file_access_count -0.2422

- DESKTOP-F768FB6 / 2026-03-30: BENIGN; if_weighted_risk -0.5169; level__named_pipe_event_count +0.4875; level__file_access_count -0.2109; level__http_request_count +0.2002; level__file_delete_count -0.1752

- DESKTOP-F768FB6 / 2026-03-17: BENIGN; if_weighted_risk -0.6190; level__named_pipe_event_count +0.4822; level__file_access_count -0.2825; level__http_request_count +0.1721; risk_minus_past7_mean -0.1441

- DATASL-173 / 2026-03-23: DATA_HOARDING; level__clipboard_copy_count +2.5076; level__file_access_count +0.4725; level__domain_access_entropy -0.0605; level__http_request_count +0.0549; if_web_network +0.0531

- DATASL-173 / 2026-03-26: BENIGN; if_weighted_risk -0.3901; level__file_access_count -0.2865; level__http_request_count +0.2114; level__file_sharing_visit_count -0.1871; level__external_connection_count +0.1852

- DATASL-173 / 2026-03-27: BENIGN; if_weighted_risk +0.4900; level__http_request_count -0.2863; level__file_access_count -0.2231; level__file_access_entropy -0.1259; risk_minus_past7_mean +0.1085

- SOCL5-19 / 2026-03-18: USB_EXFILTRATION_PRECURSOR; level__after_hours_usb_ratio +1.6670; level__file_access_count +0.5389; level__usb_connect_count -0.4826; level__http_request_count -0.4462; level__clipboard_copy_count -0.1716

- SOCL5-19 / 2026-03-19: BENIGN; if_weighted_risk -0.4746; level__file_access_count -0.3030; level__http_request_count +0.2351; level__external_connection_count +0.1914; risk_minus_past7_mean -0.0997

- SOCL5-19 / 2026-03-25: BENIGN; if_weighted_risk +0.4417; level__file_sharing_visit_count -0.1920; level__file_access_count +0.1607; risk_minus_past7_mean +0.1602; level__named_pipe_event_count -0.1121