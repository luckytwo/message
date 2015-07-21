package com;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class MessageUtil {

	/**
	 * 初始签名串
	 */
	public static final String SIGN_STR = "xhdiwjnchekd4d512chdjx5d8e4c394D2D7S";

	private static final AtomicInteger msgIdSeq = new AtomicInteger(0);

	private static final Logger logger = Logger.getLogger(MessageTest.class);

	private static final String sn = "01234567890123456789012345678901";

	/**
	 * 00041报文
	 * 
	 * @return
	 * @throws Exception
	 */
	public static ByteBuffer get00041() throws Exception {
		ByteBuf headBuf = Unpooled.buffer(40).order(ByteOrder.LITTLE_ENDIAN).writeShort(0x5A5A) // 头
				.writeByte(0x01) // 协议版本
				.writeByte(0x11) // 加密和签名标识
				.writeShort(104) // 长度
				.writeShort(0x0041).writeInt(msgIdSeq.incrementAndGet());
		writeTimestamp(headBuf, LocalDateTime.now());
		headBuf.writeInt(0).writeShort((int) (0 >> (4 * 8))).writeZero(14);

		// 加密SN
		Key secretKey = new SecretKeySpec(sign(SIGN_STR.getBytes()), "AES");
		byte[] snByte = encrypt(sn.getBytes(), secretKey);
		ByteBuffer snBuf = ByteBuffer.allocate(snByte.length);
		snBuf.put(snByte);
		snBuf.flip();

		// 签名
		ByteBuffer signBuf = ByteBuffer.allocate(SIGN_STR.getBytes().length);
		signBuf.put(SIGN_STR.getBytes());
		signBuf.flip();

		byte[] signbyte = sign(headBuf.nioBuffer(), snBuf, signBuf);

		ByteBuffer bodyBf = ByteBuffer.allocate(104);
		bodyBf.put(headBuf.nioBuffer());
		bodyBf.put(snByte);
		bodyBf.put(signbyte);

		bodyBf.flip();
		logger.info("get00041() bodyBf limit: " + bodyBf.limit() + " position:" + bodyBf.position());

		return bodyBf;
	}

	/**
	 * 0003 报文
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static ByteBuffer get00003(long appId) throws NoSuchAlgorithmException {
		ByteBuf headBuf = Unpooled.buffer(40).order(ByteOrder.LITTLE_ENDIAN).writeShort(0x5A5A).writeByte(0x01)
				.writeByte(0x01).writeShort(56).writeShort(0x0003).writeInt(msgIdSeq.incrementAndGet());

		writeTimestamp(headBuf, LocalDateTime.now());
		headBuf.writeInt((int) appId).writeShort((int) (appId >> (4 * 8))).writeZero(14);

		// 签名
		ByteBuffer signBuf = ByteBuffer.allocate(SIGN_STR.getBytes().length);
		signBuf.put(SIGN_STR.getBytes());
		signBuf.flip();
		byte[] signbyte = sign(headBuf.nioBuffer(), signBuf);

		ByteBuffer bodyBf = ByteBuffer.allocate(40 + 16);

		signBuf.flip();
		bodyBf.put(headBuf.nioBuffer());
		bodyBf.put(signbyte);

		bodyBf.flip();
		logger.info("get00003() bodyBf limit: " + bodyBf.limit() + " position:" + bodyBf.position());

		return bodyBf;
	}

	/**
	 * 0004 报文
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static ByteBuffer get00004(ByteBuffer loginStr, long appId) throws NoSuchAlgorithmException {
		ByteBuf headBuf = Unpooled.buffer(40 + 16).order(ByteOrder.LITTLE_ENDIAN).writeShort(0x5A5A).writeByte(0x01)
				.writeByte(0x01).writeShort(56).writeShort(0x0004).writeInt(msgIdSeq.incrementAndGet());

		writeTimestamp(headBuf, LocalDateTime.now());
		headBuf.writeInt((int) appId).writeShort((int) (appId >> (4 * 8))).writeZero(14);

		ByteBuffer signBuf = ByteBuffer.allocate(SIGN_STR.getBytes().length);
		signBuf.put(SIGN_STR.getBytes());

		// 签名
		ByteBuffer signTmp = ByteBuffer.allocate(SIGN_STR.getBytes().length);
		signTmp.put(SIGN_STR.getBytes());
		signTmp.flip();
		byte[] signbyte = sign(headBuf.nioBuffer(), signTmp, loginStr);

		ByteBuffer bodyBf = ByteBuffer.allocate(40 + 16);

		signTmp.flip();
		bodyBf.put(headBuf.nioBuffer());
		bodyBf.put(signbyte);

		bodyBf.flip();
		logger.info("get00003() bodyBf limit: " + bodyBf.limit() + " position:" + bodyBf.position());

		return bodyBf;
	}


	private static void writeTimestamp(ByteBuf buf, LocalDateTime ts) {
		final int milli = ts.getNano() / 1000000;
		buf.writeByte(milli);
		byte milliData = 0;
		milliData |= ts.getSecond();
		milliData |= ((milli >> 2) & 0b11000000);
		final int year = ts.getYear();
		buf.writeByte(milliData).writeByte(ts.getMinute()).writeByte(ts.getHour()).writeByte(ts.getDayOfMonth())
				.writeByte(ts.getMonthValue()).writeByte(year % 100).writeByte(year / 100);
	}

	private static byte[] sign(ByteBuffer... source) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("md5");
		for (ByteBuffer buf : source) {
			digest.update(buf);
		}

		return digest.digest();
	}

	public static byte[] sign(byte[] source) {
		MessageDigest digest = getDigest("md5");
		return digest.digest(source);
	}

	public static MessageDigest getDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			// 不会抛出该异常,除非编码错误
			throw new RuntimeException(e);
		}
	}

	public static byte[] encrypt(byte[] context, Key secretKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");// 创建密码器

		cipher.init(Cipher.ENCRYPT_MODE, secretKey);// 初始化
		byte[] result = cipher.doFinal(context);
		return result; // 加密
	}

	public static byte[] decrypt(byte[] content, Key secretKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");// 创建密码器
		cipher.init(Cipher.DECRYPT_MODE, secretKey);// 初始化
		byte[] result = cipher.doFinal(content);
		return result; // 加密
	}

	public static void main(String[] args) throws Exception {
		byte[] bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
				2};
		Key secretKey = new SecretKeySpec(sign(SIGN_STR.getBytes()), "AES");
		byte[] r = encrypt(bytes, secretKey);

		System.out.println(r.length);

		r = decrypt(r, secretKey);

		System.out.println(r[3]);

	}
}
