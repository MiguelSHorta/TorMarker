import Utils.PcapManager;
import Utils.Stats;
import com.opencsv.exceptions.CsvValidationException;
import org.pcap4j.core.NotOpenException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.util.Properties;
import java.util.Scanner;

public class InteractiveClient {
    public static int remote_port_secure;
    public static int remote_port_unsecure;
    public static String remote_host; //
    public static final int BUF_SIZE = 2048;
    private static byte[] payloadBytes = null;
    private static byte[] ack;
    private static long waitMilli = 0;
    //private static long waitNano = 0;


    public static void main(String[] argv) throws Exception {
        //TIRMMRT certificate for server side authentication
        System.setProperty("javax.net.ssl.trustStore", "./keystore/tirmmrts");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        readConfigurationFiles();

        while (true) {
            readConfigurationFiles();
            System.out.printf("Input specification: <protocol: 1> <path.pcap> <path.csv> <numberOfPackets: >50 > <watermarkType: rainbow/icbw> <amplitude> <maxAmplitude> \n\nExample input: 1 ./captures/UNBSkype30kTrain.pcap ./captures/UNBSkype30kTrain.csv 30000 rainbow 10 80\n\n");
            Scanner inFromUser = new Scanner(System.in);
            String[] paths = null;
            int protocol = 0;
            try {
                protocol = inFromUser.nextInt();
                paths = inFromUser.nextLine().trim().split(" ");
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Usage: protocol: 1-Pcap, 2-TCP, 3-TLS");
                System.exit(1);
            }
            switch (protocol) {
                case 1:
                    Socket socket = new Socket(remote_host, remote_port_unsecure);
                    OutputStream out = socket.getOutputStream();
                    InputStream in = socket.getInputStream();
                    ack = new byte[BUF_SIZE];
                    PcapManager pcapManager = new PcapManager(paths[0], paths[1], paths[2], paths[3], paths[4], paths[5]);
                    Thread.sleep(1000);
                    new Thread(() -> {
                        while(true) {
                            if (canSend())
                                // Thread responsible for sending the packets and waiting the interleaving delays between them
                                try {
                                    out.write(payloadBytes);
                                    //System.out.println(String.format("Writing packet with length: %d and waiting %d milliseconds", payloadBytes.length, waitMilli));
                                    updatePayload(null);
                                    if(waitMilli==-1) break;
                                    Thread.sleep(waitMilli, 0);
                                } catch (InterruptedException | IOException e) {
                                    e.printStackTrace();
                                }
                        }
                        System.out.println("Thread closing.\n");
                    }).start();
                    // Always running, canSend()==true means packet has been sent and thread is waiting the interleaving delay; waitMilli==-1 file has reached the end or enough packets have been sent
                    while(true){
                        if(!canSend()){
                            if(waitMilli==-1) break;
                            advanceValues(pcapManager);
                        }
                    }
                    System.out.println("Finished replaying pcap.");

                    break;
                case 2: // TIR debugging, ignore
                    try {
                        Socket tcp_socket = new Socket(remote_host, remote_port_unsecure);
                        do_TCP_TLS(tcp_socket, paths[0]);
                        tcp_socket.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    break;
                case 3: // TIR debugging, ignore
                    Socket tls_socket = getSecureSocket(remote_host, remote_port_secure);
                    do_TCP_TLS(tls_socket, paths[0]);
                    tls_socket.close();
                    break;
                default:
                    System.out.println("No such protocol");
            }
        }
    }

    /**
     * Gets new interleaving delay and payload from next packet to be sent and updates payloadBytes and waitMilli accordingly
     * @param pcapManager
     * @throws NotOpenException
     * @throws CsvValidationException
     * @throws IOException
     */
    private static synchronized void advanceValues(PcapManager pcapManager) throws NotOpenException, CsvValidationException, IOException {
        long waitTimingMilli = pcapManager.nextTiming();
        payloadBytes = pcapManager.nextPacket();
        waitMilli = waitTimingMilli;
        //waitNano = timing[1];
    }

    /**
     * Checks if payloadBytes is null
     * @return
     */
    private static synchronized boolean canSend() {
        return payloadBytes != null;
    }

    /**
     * Updates the payload to null after sending a packet so thread can start processing another one
     * @param value
     */
    private static synchronized void updatePayload(byte[] value) {
        payloadBytes = value;
    }

    /**
     * Reads the paths from config.properties file
     */
    private static void readConfigurationFiles() {

        try {
            InputStream input = new FileInputStream("./configuration/config.properties");
            Properties prop = new Properties();

            prop.load(input);

            remote_host = prop.getProperty("remote_host");
            remote_port_unsecure = Integer.parseInt(prop.getProperty("remote_port_unsecure"));
            remote_port_secure = Integer.parseInt(prop.getProperty("remote_port_secure"));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Opens a socket for TLS secured communication, not used in the dissertation's context
     * @param host
     * @param port
     * @return
     * @throws IOException
     */
    private static Socket getSecureSocket(String host, int port) throws IOException {
        SSLSocketFactory factory =
                (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
                (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();
        return socket;
    }

    /**
     * Simple HTTP requester, for debugging the Tor security enforcement, not used.
     * @param socket
     * @param path
     * @throws IOException
     */
    private static void do_TCP_TLS(Socket socket, String path) throws IOException {
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();
        Stats stats = new Stats();

        String message_str = String.format("GET %s HTTP/1.1\r\n\r\n", path);
        byte[] message = message_str.getBytes();
        System.out.println(String.format("%b", message));
        out.write(message, 0, message.length);
        System.out.println("Sent request: " + message_str + " for " + remote_host + ":" + remote_port_secure);
        out.flush();

        int n;
        byte[] buffer = new byte[BUF_SIZE];
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            stats.newRequest(n);
            //System.out.write(buffer, 0, n);
        }
        stats.printReport();
    }

}

