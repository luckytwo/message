package com;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.Key;
import java.util.Iterator;

import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

public class NioClient extends Thread {

	private static final Logger logger = Logger.getLogger(NioClient.class);

	private Selector selector = null;

	private SocketChannel sc = null;

	private ByteBuffer msgBuf = ByteBuffer.allocate(2048);

	/**
	 * 登录串
	 */
	public byte[] loginStr;

	/**
	 * 签名串
	 * 
	 */
	public ByteBuffer signKe;

	/**
	 * 
	 * 加密串
	 */
	public byte[] dataKey;

	/**
	 * 家电id
	 * 
	 */
	public long appId;

	public NioClient() throws Exception {
		selector = Selector.open();

		InetSocketAddress isa = new InetSocketAddress("127.0.0.1", 8012);
		sc = SocketChannel.open();
		sc.connect(isa);
		sc.configureBlocking(false);
		sc.register(selector, SelectionKey.OP_READ);
	}

	public void sendMessage(ByteBuffer bf) {
		try {

			while (bf.hasRemaining()) {
				sc.write(bf);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			logger.error(e.getMessage(), e);
		}
	}

	public void run() {
		try {
			while (!Thread.interrupted()) {
				int i = selector.select();
				
				System.out.println(i);

				Iterator<SelectionKey> iterator = selector.selectedKeys()
						.iterator();

				while (iterator.hasNext()) {

					SelectionKey selectionKey = iterator.next();
					iterator.remove();

					if (selectionKey.isValid()) {
						if (selectionKey.isConnectable()) {
							SocketChannel channel = (SocketChannel) selectionKey
									.channel();

							// 如果正在连接，则完成连接
							if (channel.isConnectionPending()) {
								channel.finishConnect();
							}

							channel.configureBlocking(false);
							channel.register(selector, SelectionKey.OP_READ);
							
							sendMessage(MessageUtil.get00041());
						}

						if (selectionKey.isReadable()) {
							processRead(selectionKey);
						}
					}

				}
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	private void processRead(SelectionKey selectionKey) {
		SocketChannel channel = (SocketChannel) selectionKey.channel();

		ByteBuffer bf = ByteBuffer.allocate(1024);

		try {
			int i = channel.read(bf);

			// 对方主动关闭
			if (i == -1) {
				throw new Exception("socket closed by server.");
			}

			if (i > 0) {
				bf.flip();
				msgBuf.put(bf);

				// 报文最小56
				if (msgBuf.position() >= 56) {

					// 取消息长度
					int length = getMessageLength(msgBuf);

					logger.info("Get message length:" + length);

					if (msgBuf.position() >= length) {
						byte[] bytes = new byte[length];
						msgBuf.flip();

						msgBuf.get(bytes);

						// 取消息类型
						int msgType = getMessageType(bytes);

						logger.info(" Get message:"
								+ Integer.toHexString(msgType));

						// 0x8041 登录请求回复
						if (msgType == 0x8041) {
							process8041(bytes);
						}

						// 0x8003 登录请求回复
						if (msgType == 0x8003) {
							process8003(bytes);
						}

						// 0x8004 登录请求回复
						if (msgType == 0x8004) {
							process8004(bytes);
						}

						msgBuf.compact();
					}
				}
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			logger.error(e.getMessage(), e);
			selectionKey.cancel();
			try {
				selectionKey.channel().close();
			} catch (IOException e1) {
				logger.error(e.getMessage(), e);
			}

			MessageTest.flag = true;
		}
	}

	/**
	 * 获取消息长度
	 * 
	 * @param bf
	 * @return
	 */
	private int getMessageLength(ByteBuffer bf) {
		bf.mark();
		byte[] lengthByte = new byte[2];
		msgBuf.position(4);

		msgBuf.get(lengthByte, 0, 2);

		ByteBuffer temp = ByteBuffer.allocate(2);

		temp.put(lengthByte);

		temp.order(ByteOrder.LITTLE_ENDIAN);

		temp.flip();

		bf.reset();
		return temp.getShort();
	}

	/**
	 * 获取消息类型
	 * 
	 * @param bytes
	 * @return
	 */
	private int getMessageType(byte[] bytes) {
		ByteBuffer bf = ByteBuffer.allocate(bytes.length);
		bf.put(bytes);

		byte[] typeByte = new byte[2];
		bf.position(6);
		bf.get(typeByte, 0, 2);

		ByteBuffer temp = ByteBuffer.allocate(2);

		temp.put(typeByte);
		temp.order(ByteOrder.LITTLE_ENDIAN);
		temp.flip();

		return temp.getShort() & 0xffff;
	}

	/**
	 * 处理登录请求回复，取得登录随机串
	 * 
	 * @param bytes
	 */
	public void process8003(byte[] bytes) {
		try {
			// 取出消息体
			int bodyLength = bytes.length - 40 - 16;
			byte[] body = new byte[bodyLength];

			System.arraycopy(bytes, 40, body, 0, bodyLength);

			// 解密
			Key secretKey = new SecretKeySpec(
					MessageUtil.sign(MessageUtil.SIGN_STR.getBytes()), "AES");
			body = MessageUtil.decrypt(body, secretKey);

			if (body.length != 40) {
				throw new Exception("Body length not 40.length:" + body.length);
			}

			// 登录随机串
			byte[] loginStrByte = new byte[36];
			System.arraycopy(body, 4, loginStrByte, 0, 36);

			this.loginStr = loginStrByte;

			// 写入登录认证
			ByteBuffer bf = ByteBuffer.allocate(36);
			bf.put(loginStrByte);
			bf.flip();
			ByteBuffer data = MessageUtil.get00004(bf, this.appId);

			sendMessage(data);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	/**
	 * 处理登录认证请求回复
	 * 
	 * @param bytes
	 */
	public void process8004(byte[] bytes) {
		try {

			logger.info("process 8004 set flag true.");
			MessageTest.flag = true;

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public void process8041(byte[] bytes) {
		try {
			// 取出消息体
			int bodyLength = bytes.length - 40 - 16;
			byte[] body = new byte[bodyLength];

			System.arraycopy(bytes, 40, body, 0, bodyLength);

			// 解密
			Key secretKey = new SecretKeySpec(
					MessageUtil.sign(MessageUtil.SIGN_STR.getBytes()), "AES");
			body = MessageUtil.decrypt(body, secretKey);

			if (body.length != 42) {
				throw new Exception("Body length not 42.length:" + body.length);
			}

			// 取设备ID
			byte[] appIdByte = new byte[6];
			System.arraycopy(body, 35, appIdByte, 0, 6);
			long appId = toLong(appIdByte);

			this.appId = appId;

			// 写入0003
			ByteBuffer bf = MessageUtil.get00003(appId);

			sendMessage(bf);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public static long toLong(byte[] bytes) {
		long value = 0;
		final int length = bytes.length;
		for (int i = 0; i < length; i++) {
			int shift = i * 8;
			value |= ((long) bytes[i] & 0xFF) << shift;
		}
		return value;
	}
}
