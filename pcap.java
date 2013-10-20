import jpcap.*;
import jpcap.packet.Packet;


//import java.io.Exception;
class PacketPrinter extends java.lang.Object implements PacketReceiver {
  //this method is called every time Jpcap captures a packet
  public void receivePacket(Packet packet) {
    //just print out a captured packet
   System.out.println(packet);
	byte[] header = packet.header;
	byte[] pack = packet.data;
String str = new String(pack);
String s= new String(header);
System.out.println("header: "+header+" payload: "+str);

  }
}



public class pcap {

public static void main (String args[]) throws Exception
{

boolean a = true;
//Obtain the list of network interfaces
NetworkInterface[] devices = JpcapCaptor.getDeviceList();

System.out.println(devices.length);

//for each network interface
for (int i = 0; i < devices.length; i++) {
  //print out its name and description
  System.out.println(i+": "+devices[i].name + "(" + devices[i].description+")");

  //print out its datalink name and description
  System.out.println(" datalink: "+devices[i].datalink_name + "(" + devices[i].datalink_description+")");

  //print out its MAC address
  System.out.print(" MAC address:");
  for (byte b : devices[i].mac_address)
    System.out.print(Integer.toHexString(b&0xff) + ":");
  System.out.println();

 /* //print out its IP address, subnet mask and broadcast address
  for (NetworkInterfaceAddress a : devices[i].addresses)
    System.out.println(" address:"+a.address + " " + a.subnet + " "+ a.broadcast); */

}

try{
int index= 0;  // set index of the interface that you want to open.

//Open an interface with openDevice(NetworkInterface intrface, int snaplen, boolean promics, int to_ms)
JpcapCaptor captor=JpcapCaptor.openDevice(devices[index], 65535, false, 20);

captor.setFilter("tcp && src port 6000", true);

System.out.println("waiting");
while(a){

captor.processPacket(1,new PacketPrinter());
}
captor.close();

/*
for(int j=0;j<10;j++){
  //capture a single packet and print it out
  System.out.println(captor.getPacket());
*/
}


catch(Exception e)
{}


}

 
}
