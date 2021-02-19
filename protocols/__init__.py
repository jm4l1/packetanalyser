import pywav
# from g729a.g729a import G729Adecoder


def analyse_sip(packets, port=5060, proto="UDP", analysertp=False):
    calls = get_calls(packets, port, proto)
    call_summarys = []
    for call_id in calls.keys():
        summary = analyse_call(calls[call_id])
        if analysertp:
            for branch in summary:
                if(summary[branch].get('caller_media_address') is None or summary[branch].get('called_media_address') is None):
                    continue
                if summary[branch]['final_response'] == 'OK':
                    audio_file = write_media_stream(
                        packets, summary[branch]['caller_media_address'], summary[branch]['caller_sdp_media_port'], summary[branch]['called_media_address'], summary[branch]['called_sdp_media_port'], summary[branch]['codec'], proto, branch)
                    summary[branch]['audio_file'] = audio_file
        call_summarys.append(summary)
    return call_summarys


def write_media_stream(packets, caller_ip, caller_port, called_ip, called_port, codec, proto, file_name):
    file_name = "call_audio/" + file_name
    in_byte_stream = ""
    out_byte_stream = ""
    output_audio_in = pywav.WavWrite(file_name + "_in.raw", 1, 8000, 8, 7)
    output_audio_out = pywav.WavWrite(file_name + "_out.raw", 1, 8000, 8, 7)

    for p in packets:
        if p.transport_layer != proto:
            continue
        if p[proto].dstport == caller_port and p[proto].srcport == called_port:
            media_layer = p['RTP']
            in_byte_stream = in_byte_stream + \
                "".join(media_layer.payload.split(":"))
        if p[proto].srcport == caller_port and p[proto].dstport == called_port:
            media_layer = p['RTP']
            out_byte_stream = out_byte_stream + \
                "".join(media_layer.payload.split(":"))

    # wave_write.write(raw_data)
    # output_audio.write(raw_data)
    raw_data_in = bytearray.fromhex(in_byte_stream)
    raw_data_out = bytearray.fromhex(out_byte_stream)

    # if codec == "G729":
    #     decoder = G729Adecoder()
    #     raw_data_in = decoder.process(raw_data_in)
    #     raw_data_out = decoder.process(raw_data_out)

    output_audio_in.write(raw_data_in)
    output_audio_out.write(raw_data_out)

    # wave_write.close()
    output_audio_in.close()
    output_audio_out.close()
    return file_name


def get_calls(packets, port, proto):
    calls = {}
    for p in packets:
        if p.transport_layer != proto:
            continue
        if int(p[proto].srcport) != port and int(p[proto].dstport) != port:
            continue
        if(p.highest_layer != "SIP"):
            continue
        sip_header = p['SIP']
        call_id = get_call_id(sip_header)
        if calls.get(call_id) is None:
            calls[call_id] = []
        calls[call_id].append(sip_header)
    return calls


def analyse_call(messages):
    call_summary = {}
    for message in messages:
        fields = message.field_names
        if "request_line" in fields:
            if message.method == "REGISTER":
                via_branch = message.via_branch
                if call_summary.get(via_branch) is None:
                    call_summary[via_branch] = {}
                call_summary[via_branch]['user'] = message.from_user
                call_summary[via_branch]['contact'] = message.contact_parameter
                if message.get('expires') is not None:
                    call_summary[via_branch]['type'] = "REGISTER"
                    call_summary[via_branch]['expire_requested'] = message.expires
                if message.get("contact_parameter") is not None and message.get("contact_parameter") == "expires=0":
                    call_summary[via_branch]['type'] = "Unresgiter"

            elif message.method == "INVITE":
                via_branch = message.via_branch
                if call_summary.get(via_branch) is None:
                    call_summary[via_branch] = {}
                call_summary[via_branch]['caller'] = message.from_user
                call_summary[via_branch]['called'] = message.to_user
                call_summary[via_branch]['caller_media_address'] = message.sdp_connection_info_address
                call_summary[via_branch]['caller_sdp_media_port'] = message.sdp_media_port

        if "status_line" in fields:
            via_branch = message.via_branch
            if message.cseq_method == "REGISTER":
                if call_summary.get(via_branch) is None:
                    call_summary[via_branch] = {}
                call_summary[via_branch]['Final Ack'] = True
            if message.cseq_method == "INVITE":
                if message.status_code == "100":
                    continue
                if message.status_code.startswith("18"):
                    if call_summary.get(via_branch) is None:
                        call_summary[via_branch] = {}
                    if int(message.content_length) > 0:
                        call_summary[via_branch]['called_media_address'] = message.sdp_connection_info_address
                        call_summary[via_branch]['called_sdp_media_port'] = message.sdp_media_port
                        call_summary[via_branch]['codec'] = message.sdp_mime_type

                if message.status_code == "200":
                    if call_summary.get(via_branch) is None:
                        call_summary[via_branch] = {}
                    if int(message.content_length) > 0:
                        call_summary[via_branch]['called_media_address'] = message.sdp_connection_info_address
                        call_summary[via_branch]['called_sdp_media_port'] = message.sdp_media_port
                        call_summary[via_branch]['codec'] = message.sdp_mime_type
                    call_summary[via_branch]['final_response'] = message.status_line.split(" ")[
                        2]
                    call_summary[via_branch]['final_response_code'] = message.status_code
                    continue

                if str(message.status_code).startswith("4") or message.status_code.startswith("5") or message.status_code.startswith("6"):
                    if call_summary.get(via_branch) is None:
                        call_summary[via_branch] = {}
                    call_summary[via_branch]['final_response'] = message.status_line.split(" ")[
                        2]
                    call_summary[via_branch]['final_response_code'] = message.status_code
                    continue

                if call_summary.get(via_branch) is None:
                    call_summary[via_branch] = {}
                call_summary[via_branch]['Final Ack'] = True

    return call_summary


def get_request_line(header):
    return header.request_line


def get_status_line(header):
    return header.status_line


def get_call_id(header):
    return header.call_id


def get_from_tag(header):
    return header.from_tag


def get_to_tag(header):
    return header.to_tag
