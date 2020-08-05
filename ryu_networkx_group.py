from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import switches, event, api
from ryu.lib import hub

import networkx as nx
import pylab
import matplotlib.pyplot as plt
import time
import sys

centralGraph = nx.Graph()
numSecs = 1

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.firstPacket = True
        self.rawLinks = []
        self.switches = []
        self.hosts = []
        self.srcLinks = []
        self.dstLinks = []
        self.hostLinks = []
        self.usageList = []
        self.byteCounts = []
        self.prevByteCounts = []
        self.temp = []
        self.datapaths = {}
        self.pos = nx.spring_layout(centralGraph)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)  
            hub.sleep(numSecs)
            temp = self.byteCounts
            rawLinks1 = []
            rawLinks2 = []
            if(len(self.prevByteCounts) != 0):
              self.byteCounts = [(x - y) for (x, y) in zip(self.byteCounts, self.prevByteCounts)]
              #print(len(self.rawLinks),len(self.byteCounts),'yooo')
              #print(self.rawLinks)
              for i in range(0, len(self.rawLinks)):
                print(self.byteCounts[i],i)
                if self.byteCounts[i] <= 9375: #75kb --->  9357 B
                  rawLinks1.append(self.rawLinks[i])
                else:
                  rawLinks2.append(self.rawLinks[i])
            self.prevByteCounts = temp
            plt.clf()
            nx.draw_networkx_edges(centralGraph, self.pos, ax=None, edgelist=rawLinks1, edge_color='black', arrows=False)
            nx.draw_networkx_edges(centralGraph, self.pos, ax=None, edgelist=rawLinks2, edge_color='r', arrows=False)
            nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.switches, node_size=1500, node_color='g')
            nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.hosts, node_size=1500, node_color='y')
            nx.draw_networkx_labels(centralGraph, self.pos, ax=None)
            plt.axis('off')
            plt.draw() 
            plt.pause(0.001)
            self.byteCounts = [0] * len(self.rawLinks)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
          src_node = ev.msg.datapath.id
          src_port = stat.port_no
          if(src_port == 4294967294): # connection to controller, ignore for now
            continue
          total_bytes = stat.tx_bytes + stat.rx_bytes
          pair = self.findLink(src_node, src_port, total_bytes)
          self.addBytes(pair, total_bytes)


    def findLink(self, srcNode, srcPort, totalBytes):
      # search through switch list
      for elem in self.srcLinks:
        if((elem[1] == srcNode or elem[0] == srcNode) and elem[2]['port'] == srcPort):
          return (elem[0], elem[1])
      for elem in self.hostLinks:
        if(elem[1] == srcNode and elem[2]['port'] == srcPort):
          return (elem[0], elem[1])
      print('not found (SOMETHING IS WRONG!)')
      return

    def addBytes(self, pair, totalBytes):
      i = 0
      for rawPair in self.rawLinks:
        pairFlip = (pair[1], pair[0])
        if(pair == rawPair) or (pairFlip == rawPair):
          self.byteCounts[i] += totalBytes
          return
        i += 1
      print('could not add bytes (SOMETHING IS WRONG!')
      return


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if(self.firstPacket == True):
          self.monitor_thread = hub.spawn(self._monitor) #only start monitor when controller is ready
          self.firstPacket = False
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)



    def get_topology_data(self, ev):
      switchList = api.get_all_switch(self)
      linkList = api.get_all_link(self)
      self.switches = [switch.dp.id for switch in switchList]
      self.srcLinks = [(link.src.dpid, link.dst.dpid, {'port':link.src.port_no}) for link in linkList]
      self.dstLinks = [(link.dst.dpid, link.src.dpid, {'port':link.dst.port_no}) for link in linkList]
      self.constructGraph()

    def get_topology_data_wait(self, ev):
      time.sleep(0.5) #need to wait here, switch is changing its openflow version
      self.get_topology_data(ev)


    def constructGraph(self):
      plt.clf()
      centralGraph.clear()
      if(len(self.switches) == 0): # deals with case of empty graph
        nx.draw(centralGraph)
        plt.draw()
      self.getRawData()
      centralGraph.add_nodes_from(self.switches)
      centralGraph.add_nodes_from(self.hosts)
      centralGraph.add_edges_from(self.rawLinks)
      self.pos = nx.spring_layout(centralGraph, k=0.25)
      nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.switches, node_size=1500, node_color='g')
      nx.draw_networkx_nodes(centralGraph, self.pos, ax=None, nodelist=self.hosts, node_size=1500, node_color='y')
      nx.draw_networkx_edges(centralGraph, self.pos, ax=None, width = 1, edge_color='b')
      nx.draw_networkx_labels(centralGraph, self.pos, ax=None)
      plt.axis('off')
      plt.draw()
      plt.pause(0.001)

    def getRawData(self): # gets raw data for graph drawing
      self.rawLinks = []
      raw1 = []
      raw2 = []
      for elem in self.srcLinks:
        if(elem[1], elem[0]) not in raw1:
          raw1.append((elem[0], elem[1]))
      raw2 = [(elem[1], elem[0]) for elem in self.hostLinks]
      self.rawLinks = sorted(raw1 + raw2)
      self.byteCounts = [0] * len(self.rawLinks)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
      self.get_topology_data_wait(ev)

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
      self.get_topology_data_wait(ev)

    @set_ev_cls(event.EventHostAdd)
    def switch_leave_handler(self, ev):
      hostList = api.get_all_host(self)
      self.hosts = [host.mac for host in hostList]
      self.hostLinks = [(host.mac, host.port.dpid, {'port':host.port.port_no, 'bytes':0}) for host in hostList]
      self.get_topology_data(ev)