package coe817project;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Supervisor {
	private DataOutputStream out;
    private Socket socket;
    private ServerSocket server;
    private DataInputStream in;
    
    public Supervisor(int port) {
    	try {
            
            server = new ServerSocket(port);
            System.out.println("Supervisor started");
            System.out.println("Waiting for client ...");
            
            socket = server.accept();
            System.out.println("Client accepted"+"\n");
            
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());     
            
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String messagein = "";
            String messageout = "";
            
    	}catch(IOException i){
            System.out.println(i);
        }
    }
    
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException{       
        Supervisor initiator = new Supervisor(6666);
    }
}
