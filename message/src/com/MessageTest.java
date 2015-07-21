package com;


import org.apache.log4j.Logger;

public class MessageTest {

	private static final Logger logger = Logger.getLogger(MessageTest.class);

	/**
	 * 标识client线程业务完成
	 */
	public static volatile boolean flag = false;

	public static void main(String[] args) {
		
		
		NioClient client = null;
		
		try {
			flag = false;
			client = new NioClient();
			client.start();
//			client.sendMessage(MessageUtil.get00041());
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			System.exit(0);
		}		

		while (true) {			
			
			if(flag)
			{
				client.interrupt();
				
				try {
					flag = false;
					client = new NioClient();
					client.start();
//					client.sendMessage(MessageUtil.get00041());
				} catch (Exception e) {
					logger.error(e.getMessage(), e);
				}
			}
			
			
			try {
				Thread.sleep(3 * 1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				logger.error(e.getMessage(), e);
			}
		}
	}

}
