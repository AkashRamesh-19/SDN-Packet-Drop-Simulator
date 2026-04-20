from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

tcp_count = 0
udp_count = 0
icmp_count = 0

def _handle_PacketIn(event):
    global tcp_count, udp_count, icmp_count

    try:
        packet = event.parsed
        if not packet.parsed:
            return

        ip_packet = packet.find('ipv4')

        if ip_packet:
            proto = ip_packet.protocol

            if proto == 6:
                tcp_count += 1
                print("TCP Packet Count:", tcp_count)

            elif proto == 17:
                udp_count += 1
                print("UDP Packet Count:", udp_count)

            elif proto == 1:
                icmp_count += 1
                print("ICMP Packet Count:", icmp_count)

    except Exception as e:
        # Prevent crash from POX parsing issues
        pass

    # Forward packet
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Traffic Classification Controller Started")