package Utils;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;


import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;


public class PcapManager {
    private PcapHandle capHandler;
    private CSVReader timingsReader;
    InputStream in;
    double previousTiming;
    int packetsToSend;
    int counter;
    int flowSize = 350;
    boolean divideFlow = false;
    double[][] intervals = {{12,8.5,8,7.5}, {10.5,4.5,5.5,9}, {0.5,13.5,1.5,3}, {11,2.5,7,5}};
    double intervalSize = 0.5;
    long maxAbsDelay = 80;
    long timingBuffer = 50;
    String watermarkType;
    long[] delays;
    long amplitude;
    Random generator = new Random(1l);
    String capturePath;
    String timingsPath;

    public PcapManager(String capturePath, String timingsPath, String packetsToSend, String watermarkType, String amplitude, String maxAmp) throws PcapNativeException, NotOpenException, IOException, CsvValidationException, InterruptedException {
        this.capturePath = capturePath;
        this.timingsPath = timingsPath;
        openCapture();
        this.watermarkType = watermarkType;
        this.packetsToSend = Integer.parseInt(packetsToSend);
        previousTiming = 0;
        this.amplitude = Long.parseLong(amplitude);
        this.maxAbsDelay = Long.parseLong(maxAmp);
        embedWatermark();
    }

    /**
     * Opens the capture file with the packets and .csv with the interleaving timings
     * @throws PcapNativeException
     * @throws IOException
     * @throws NotOpenException
     * @throws CsvValidationException
     * @throws InterruptedException
     */
    private void openCapture() throws PcapNativeException, IOException, NotOpenException, CsvValidationException, InterruptedException {
        System.out.println("Attempting to open capture file in path: " + capturePath);
        capHandler = Pcaps.openOffline(capturePath);

        System.out.println("Attempting to open csv file in path: " + timingsPath);
        timingsReader = new CSVReader(new FileReader(timingsPath));
        timingsReader.readNext();
        previousTiming = Double.parseDouble(timingsReader.readNext()[0]);
        counter = 0;
    }

    /**
     * Crafts the interleaving times for the specific watermarks or just processes the real times in case no watermark is selected.
     * @throws CsvValidationException
     * @throws IOException
     * @throws NotOpenException
     * @throws PcapNativeException
     * @throws InterruptedException
     */
    private void embedWatermark() throws CsvValidationException, IOException, NotOpenException, PcapNativeException, InterruptedException {

        String line[];
        delays = new long[packetsToSend];
        double totalReplayTime = 0;
        switch (watermarkType.toLowerCase()){
            case "rainbow":
                System.out.println("Crafting Rainbow watermark...");
                long minDelta = 0;
                long maxDelta = 0;
                while(maxAbsDelay != Math.abs(minDelta) || maxAbsDelay != Math.abs(maxDelta)) {
                    long currentDelta = 0;
                    minDelta = 0;
                    maxDelta = 0;
                    for (int i = 0; i < packetsToSend; i++) {

                        if(Math.abs(currentDelta) == maxAbsDelay)
                            if(currentDelta < maxAbsDelay) currentDelta += amplitude;
                            else currentDelta -= amplitude;
                        else if (generator.nextDouble() < 0.4999) currentDelta += amplitude;
                        else currentDelta -= amplitude;

                        if (currentDelta < minDelta) minDelta = currentDelta;
                        if (currentDelta > maxDelta) maxDelta = currentDelta;

                            delays[i] = currentDelta + maxAbsDelay;
                        //System.out.print(String.format("|%d", delays[i]));
                    }

                    //System.out.print(minDelta + " ");
                    //System.out.println(maxDelta);
                }

                //for (int i = 1; i < 24000; i++) {
                //    timingsReader.readNext();
                //}

                //line = timingsReader.readNext();
                //Double currentTiming = (Double.parseDouble(line[0]));
                //previousTiming = currentTiming;

                System.out.println();
                for (int i = 0; i < packetsToSend; i++) {
                    if ((line = timingsReader.readNext()) != null) {
                        Double currentTiming = (Double.parseDouble(line[0]));
                        long microIPD = Math.round((currentTiming - previousTiming) * 1000000);
                        previousTiming = currentTiming;
                        delays[i] += (microIPD / 1000);
                        totalReplayTime += delays[i];
                        //System.out.print(String.format("|%d", delays[i]));
                    } else delays[i] = -1;
                }

                System.out.println(String.format("Finished crafting rainbow watermark, amp set to %d and max amp set to %d", amplitude, maxAbsDelay));

                break;

            case "icbw":
                System.out.println("Crafting icbw watermark...");
                double currentInterval = -1;
                Double currentTiming;
                /*for (int i = 1; i < 0; i++) timingsReader.readNext();
                    line = timingsReader.readNext();
                    currentTiming = (Double.parseDouble(line[0]));
                    previousTiming = currentTiming;*/

                for (int i = 0; i < packetsToSend; i++) {
                    if ((line = timingsReader.readNext()) != null) {
                        currentTiming = (Double.parseDouble(line[0]));
                        long microIPD = Math.round((currentTiming - previousTiming) * 1000000);
                        previousTiming = currentTiming;

                        while(currentTiming > 15) currentTiming-=15;

                        boolean found = false;
                        if(currentTiming > currentInterval && currentTiming < currentInterval+intervalSize){
                            found = true;
                            delays[i] = amplitude + (microIPD / 1000);
                        } else for (int j = 0; j < 4 && !found; j++)
                            for (int k = 0; k < 4 && !found; k++)
                                if(currentTiming > intervals[j][k] && currentTiming < intervals[j][k]+intervalSize) {
                                    currentInterval = intervals[j][k];
                                    delays[i] = amplitude + (microIPD / 1000);
                                    found = true;
                                }

                        if(!found) delays[i] = (microIPD / 1000);

                        System.out.print(String.format("|%d", delays[i]));
                        totalReplayTime += delays[i];
                    } else delays[i] = -1;
                }

                System.out.println(String.format("Finished crafting icbw watermark, amp set to %d", amplitude));
                break;

            default:
                System.out.println("Processing pcap...");
                for (int i = 0; i < packetsToSend; i++)
                    if ((line = timingsReader.readNext()) != null) {
                        currentTiming = (Double.parseDouble(line[0]));
                        long microIPD = Math.round((currentTiming - previousTiming) * 1000000);
                        delays[i] = (microIPD / 1000);
                        previousTiming = currentTiming;
                        totalReplayTime += delays[i];
                    } else delays[i] = -1;
        }

        System.out.printf("Replay time will be %f seconds", (totalReplayTime/1000) + (timingBuffer*packetsToSend/1000));
    }

    public synchronized long nextTiming() throws NotOpenException, CsvValidationException, IOException {

        long waitTimingMilli = delays[counter++];
        if(counter==packetsToSend)
            return -1;
        //if(divideFlow && counter%flowSize<2) waitTimingMilli+=3500;
        //System.out.println(waitTimingMilli - maxDelay);

        return waitTimingMilli + timingBuffer;
    }

    public byte[] nextPacket() throws NotOpenException {
        return capHandler.getNextPacket().getPayload().getPayload().getPayload().getRawData();
    }

    // Debugging purposes ignore
    public void replayPcap() throws CsvValidationException, IOException, NotOpenException, PcapNativeException, InterruptedException {
        System.out.println("Replaying the capture file...");

        double currentTiming = 0;
        String[] line = timingsReader.readNext();
        Packet packet;
        byte[] payloadBytes = null;
        long microIPD = 0;
        long milliIPD = 0;
        long nanoIPD = 0;


        /*while ((packet = capHandler.getNextPacket()) != null && (line = timingsReader.readNext()) != null) {
            currentTiming = (Double.parseDouble(line[0]));
            microIPD = Math.round((currentTiming - previousTiming) * 1000000);
            milliIPD = microIPD / 1000;
            nanoIPD = (microIPD - milliIPD * 1000) * 1000;
            payloadBytes = packet.getPayload().getPayload().getPayload().getRawData();
            previousTiming = currentTiming;

            Thread.sleep(milliIPD, (int) nanoIPD);

            //System.out.println(String.format("Packet length: %d Raw data length: %d Payload: ->%s", packet.length(), packet.getRawData().length,  packet.getPayload().getPayload().getPayload().length()));
            out.write(payloadBytes);
            //System.out.println(String.format("CSVTiming: %.6f CSVLength: %s PcapLength: %d", timing, line[1], packet.length()));
        }*/
        //long processing;
        /*while (true) {
            //processing = System.nanoTime();
            packet = capHandler.getNextPacket();
            line = timingsReader.readNext();
            if (packet == null || line == null) break;
            currentTiming = (Double.parseDouble(line[0]));
            microIPD = Math.round((currentTiming - previousTiming) * 1000000);
            milliIPD = microIPD / 1000;
            nanoIPD = (microIPD - milliIPD * 1000) * 1000;
            payloadBytes = packet.getPayload().getPayload().getPayload().getRawData();
            previousTiming = currentTiming;

            Thread.sleep(milliIPD, (int) nanoIPD);

            //System.out.println(String.format("Packet length: %d Raw data length: %d Payload: ->%s", packet.length(), packet.getRawData().length,  packet.getPayload().getPayload().getPayload().length()));
            out.write(payloadBytes);
            //System.out.println(String.format("CSVTiming: %.6f CSVLength: %s PcapLength: %d", timing, line[1], packet.length()));
        }*/

        while (true) {
            packet = capHandler.getNextPacket();
            line = timingsReader.readNext();
            if (packet == null || line == null) break;
            currentTiming = (Double.parseDouble(line[0]));
            milliIPD = Math.round((currentTiming - previousTiming) * 1000);
            payloadBytes = packet.getPayload().getPayload().getPayload().getRawData();
            previousTiming = currentTiming;

            Thread.sleep(milliIPD);

            //out.write(payloadBytes);
            //System.out.println(String.format("Packet length: %d Raw data length: %d Payload: ->%s", packet.length(), packet.getRawData().length,  packet.getPayload().getPayload().getPayload().length()));
            //System.out.println(String.format("CSVTiming: %.6f CSVLength: %s PcapLength: %d", timing, line[1], packet.length()));
        }

        System.out.println("Finished replaying the file.");
    }

    // Debugging purposes ignore
    public void replaySinglePacket(int n) throws NotOpenException, PcapNativeException {
        Packet packet = null;
        for (int i = 0; i < n; i++) {
            packet = capHandler.getNextPacket();
        }
        System.out.println("Sending packet:\n" + packet);
        //injector.sendPacket(packet);
    }

}

