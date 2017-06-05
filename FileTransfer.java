import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class FileTransfer {

	public static void main(String[] args) {
		try {

			Socket socket;
			String fileName;
			int port;
			String host;
			SecretKey sessionKey = null;
			int numberOfChunks = 1024;

			ObjectOutputStream soos;
			ObjectInputStream sois;

			switch (args[0]) {
			case "makekeys":
				try {

					KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
					// you can use 2048 for faster key generation
					gen.initialize(4096);

					KeyPair keyPair = gen.genKeyPair();
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();

					ObjectOutputStream oosPublic = new ObjectOutputStream(new FileOutputStream(new File("public.bin")));
					oosPublic.writeObject(publicKey);

					ObjectOutputStream oosPrivate = new ObjectOutputStream(
							new FileOutputStream(new File("private.bin")));
					oosPrivate.writeObject(privateKey);

					oosPrivate.close();
					oosPublic.close();
				} catch (NoSuchAlgorithmException | IOException e) {
					e.printStackTrace(System.err);
				}
				break;
			case "server":
				// Name of the file that contains the private key
				fileName = args[1];
				// Port number the server will listen on
				port = Integer.parseInt(args[2]);

				String outputPath = "test2.txt";
				boolean isInitiated = false;
				int seqNumber = 0;
				int len = 0;
				FileOutputStream file = new FileOutputStream(new File(outputPath));

				ServerSocket serverSocket = new ServerSocket(port);

				while (true) {

					// Wait for a client to connect
					socket = serverSocket.accept();

					soos = new ObjectOutputStream(socket.getOutputStream());
					sois = new ObjectInputStream(socket.getInputStream());
					ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(fileName)));

					PrivateKey privateKey = (PrivateKey) ois.readObject();

					while (true) {

						Message message = (Message) sois.readObject();

						// If the client sends a DisconnectMessage, the server
						// should close the connection and wait for a new one.
						if (message.getType() == MessageType.DISCONNECT) {

							socket.close();
							isInitiated = false;
							seqNumber = 0;
							break;

						} else if (message.getType() == MessageType.START) {

							// Prepare for a file transfer based on the
							// information in the message
							try {

								// Decrypt the session key passed by the client
								StartMessage startMessage = (StartMessage) message;
								Cipher c = Cipher.getInstance("RSA");
								c.init(Cipher.UNWRAP_MODE, privateKey);
								sessionKey = (SecretKey) c.unwrap(startMessage.getEncryptedKey(), "AES",
										Cipher.SECRET_KEY);

								soos.writeObject(new AckMessage(0));

								isInitiated = true;
								seqNumber = 0;
								numberOfChunks = (int) Math
										.ceil(startMessage.getSize() / (double) startMessage.getChunkSize());

								// Incase the chunk size is bigger than the
								// bytes left in the file
								len = (int) (startMessage.getSize() % startMessage.getChunkSize());

							} catch (InvalidKeyException e) {
								soos.writeObject(new AckMessage(-1));
							}

						} else if (message.getType() == MessageType.STOP) {

							soos.writeObject(new AckMessage(-1));
							isInitiated = false;
							seqNumber = 0;

						} else if (message.getType() == MessageType.CHUNK && isInitiated) {

							Chunk chunkMessage = (Chunk) message;

							// The Chunk’s sequence number must be the
							// next expected sequence number by the server
							if (chunkMessage.getSeq() == seqNumber) {

								// Decrypt the data
								Cipher cipher = Cipher.getInstance("AES");
								cipher.init(Cipher.DECRYPT_MODE, sessionKey);
								byte[] decryptedData = cipher.doFinal(chunkMessage.getData());

								// Calculate the CRC32 value for the
								// decrypted data and compare it with
								// the CRC32 value included in the chunk
								CRC32 crc32 = new CRC32();
								crc32.update(decryptedData);

								if ((int) crc32.getValue() == chunkMessage.getCrc()) {

									// Accept the chunk and store the data
									// Check if the last chunk has extra data
									if ((seqNumber + 1) == numberOfChunks) {
										file.write(decryptedData, 0, len);
									} else
										file.write(decryptedData);
									System.out.println("Chunk received [" + ++seqNumber + "/" + numberOfChunks + "]");

									// Respond with an AckMessage with sequence
									// number of the next expected chunk
									soos.writeObject(new AckMessage(seqNumber));

									if (seqNumber == numberOfChunks) {
										System.out.println("Transfer complete.\nOutput path: " + outputPath);
										isInitiated = false;
									}
								} else {
									soos.writeObject(new AckMessage(0));
									System.out.println("CRC Not Equal");
								}

							} else {
								soos.writeObject(new AckMessage(0));
								System.out.println("Chunk seq != i");
							}
						}
						message = null;
					}
				}
			case "client":
				// Name of the file that contains the public key
				fileName = args[1];
				// Host to connect to (where the server is running)
				host = args[2];
				// Port number the server is listening on
				port = Integer.parseInt(args[3]);

				int chunkSize = 0;

				socket = new Socket(host, port);
				soos = new ObjectOutputStream(socket.getOutputStream());
				sois = new ObjectInputStream(socket.getInputStream());
				ObjectInputStream oisPublic = new ObjectInputStream(new FileInputStream(new File(fileName)));
				PublicKey publicKey = (PublicKey) oisPublic.readObject();
				Scanner input;

				System.out.println("Connected to server: " + socket.getInetAddress());

				while (true) {
					// Generate an AES session key
					KeyGenerator keyGen = KeyGenerator.getInstance("AES");
					keyGen.init(128);
					sessionKey = keyGen.generateKey();

					// Encrypt the session key using the server’s public key.
					// Use Cipher.WRAP MODE to encrypt the key.
					Cipher c = Cipher.getInstance("RSA");
					c.init(Cipher.WRAP_MODE, publicKey);
					byte[] key = c.wrap(sessionKey);

					// Prompt the user to enter the path for a file to transfer.
					input = new Scanner(System.in);
					System.out.print("Enter path: ");
					String pathName = input.nextLine();
					File pathFile = new File(pathName);

					// If the path is valid, ask the user to enter the desired
					// chunk size in bytes (default of 1024 bytes)
					chunkSize = 1024;
					if (pathFile.exists()) {
						System.out.print("Enter chunk size [1024]: ");
						if ((chunkSize = input.nextInt()) > 1024)
							chunkSize = 1024;
					} else
						System.out.println("Error: File not found.");

					// Send the server a StartMessage that contains the file
					// name, length of the file in bytes, chunk size, and
					// encrypted session key.
					StartMessage startMessage = new StartMessage(pathName, key, chunkSize);
					long fileSize = startMessage.getSize();
					System.out.println("Sending: " + pathName + ". File Size: " + fileSize);
					soos.writeObject(startMessage);

					// The server should respond with an AckMessage
					// with sequence number 0 if the transfer can proceed,
					// otherwise the sequence number will be -1.
					AckMessage ackMessage = (AckMessage) sois.readObject();

					// The client should then send each chunk of the file in
					// order. After each chunk, wait for the server to respond
					// with the appropriate AckMessage.
					if (ackMessage.getSeq() == 0) {

						FileInputStream fis = new FileInputStream(pathFile);
						byte[] data;

						numberOfChunks = (int) Math.ceil(fileSize / (double) chunkSize);
						System.out.println("Sending " + numberOfChunks + " chunks...");

						for (int i = 0; i < numberOfChunks;) {

							// For each chunk, first read the data from the file
							// and store in an array based on the chunk size.
							data = new byte[chunkSize];
							fis.read(data);

							// Calculate the CRC32 value for the chunk.
							CRC32 crc = new CRC32();
							crc.update(data);

							// Encrypt the chunk data using the session key.
							Cipher c2 = Cipher.getInstance("AES");
							c2.init(Cipher.ENCRYPT_MODE, sessionKey);
							byte[] encryptedData = c2.doFinal(data);
							Chunk chunk = new Chunk(i, encryptedData, (int) crc.getValue());
							soos.writeObject(chunk);

							// After each chunk, wait for the server to respond
							// with the appropriate AckMessage
							ackMessage = (AckMessage) sois.readObject();
							if (ackMessage.getSeq() == ++i)
								System.out.println("Chunks completed [" + i + "/" + numberOfChunks + "]");
						}

						fis.close();
					}

					// Can either begin a new file transfer or disconnect
					while (true) {
						System.out.println(
								"Transfer complete.\nWould you like to?\nN - new file transfer\nD - disconnect");
						input.nextLine();
						String choice = input.nextLine();
						if (choice.equalsIgnoreCase("N"))
							break;
						else if (choice.equalsIgnoreCase("D")) {
							soos.writeObject(new DisconnectMessage());
							System.exit(0);
						} else
							System.out.println("Incorrect Input. Please Try Again.");
					}

				}
			default:
				break;
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}

	}
}