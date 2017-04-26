/*
 * Copyright © 2015 Copyright(c) linfx7, inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.ipsec.utils.tcp;

import org.opendaylight.ipsec.utils.ByteTools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class TCPClient {
    private String address;
    private int port;
    private String result;

    /**
     * Build tcp client.
     * @param address ip address of service
     * @param port port of service
     */
    public TCPClient(String address, int port) {
        this.address = address;
        this.port = port;
    }

    /**
     * Send messages.
     * @param request words to send
     * @param callback handleMessage the return value
     */
    public void send(byte[] request, TCPClientCallback callback) {
        new SendThread(address, port, request, callback).start();
    }

    private void setResult(String result) {
        this.result = result;
    }

    public String getResult() {
        return this.result;
    }

    class SendThread extends Thread {
        private String address;
        private int port;
        private byte[] request;
        private TCPClientCallback callback;

        public SendThread(String address, int port, byte[] request, TCPClientCallback callback) {
            this.address = address;
            this.port = port;
            this.request = request;
            this.callback = callback;
        }

        public void run() {
            Socket socket = null;
            try {
                socket = new Socket(address, port);
                System.out.println("connect to server: success!");
                // send request bytes
                OutputStream outputStream = socket.getOutputStream();
                ByteTools.writeStream(outputStream, request);
                outputStream.flush();
                // get response bytes
                InputStream inputStream = socket.getInputStream();
                byte[] response = ByteTools.readStream(inputStream);
//                byte [] response = "hello, world!".getBytes();
                inputStream.close();
                outputStream.close();
                // call the callback interface
                callback.deal(address, response);

                // result Returned by server
                setResult(new String(response));
                System.out.println(result);

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (socket != null) {
                        socket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) {
        TCPClient client = new TCPClient("192.168.90.130", 2020);
        client.send("Hello, World!".getBytes(), new TCPClientCallback() {
            @Override
            public void deal(String address, byte[] response) {
//                System.out.println(new String(response));
            }
        });
    }
}
