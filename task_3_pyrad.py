#!/usr/bin/python
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from StringIO import StringIO

mdict = StringIO("ATTRIBUTE User-Name 1 string\n"+
                "ATTRIBUTE User-Password 1 string\n"+
                "ATTRIBUTE NAS-Identifier 1 ipaddr")
srv = Client(server='10.0.0.10', secret='secrect',dict=Dictionary(mdict))

req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name='behner',
    NAS_Identifier='172.17.0.19')
req['User-Password']=req.PwCrypt('put password here')

reply = srv.SendPacket(req)
if reply.code == pyrad.packet.AccessAccept:
    print "access granted"
else:
    print "access denied"
