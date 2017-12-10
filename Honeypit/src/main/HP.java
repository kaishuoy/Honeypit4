package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.net.MalformedURLException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//WARNING: [SetPropertiesRule]{Server} Setting property 'URIEncoding' to 'UTF-8' did not find a matching property
/**
 * Servlet implementation class HP
 */
@WebServlet("/HP")
public class HP extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	private static boolean detected;
	private List<Rule> rules = new ArrayList<Rule>();

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public HP() {
		super();
		rules.add(new PTRule());
		rules.add(new PT2Rule());
		rules.add(new XSSRule());
		rules.add(new SQLIRule());
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		long ct = System.currentTimeMillis();
		if (request != null)
			request.setCharacterEncoding("UTF-8");
		response.setContentType("text/html; charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		PrintWriter out = response.getWriter();
				
		// preprocess
		detected = false;
		Map<String, String> data = preprocess(request);
		Map<String, String> newData = new HashMap<String, String>();
		for (Map.Entry<String, String> ent : data.entrySet()) {
			//System.out.println(ent.getValue());
			for(Rule r:rules){
				if(r.detect(ent.getValue())){
					detected = true;
					newData.put(ent.getKey(), r.generateResponse(ent.getValue()));
					break;
				}
			}
			//newData.put(ent.getKey(), evaluateExploit(ent.getValue()));
		}
		out.println("post processing<br/>");
		for (Map.Entry<String, String> ent : newData.entrySet()) {
			out.println(ent.getKey() + " " + ent.getValue());
			out.println("<br/>");
		}
		if(detected){
			//System.out.println("detected");
			logRequest(request,ct);
		}
//		else{
//			//response.setStatus(403);
//		}
		
		sendNewData(newData);
		//response.sendRedirect("");

	}

	private void logRequest(HttpServletRequest request, long time) throws IOException {
		// add entry in log
		File log = new File("D:/log.txt");
		PrintWriter logwriter = new PrintWriter(log);
		logwriter.println(Date.from(Instant.ofEpochMilli(time))+" - ID : "+time+" - From: "+ request.getRemoteAddr());
		// dump log of this request into logs folder
		File f = new File("D:/logs/"+time+".request");
		f.getParentFile().mkdirs();
		f.createNewFile();
		PrintWriter writer = new PrintWriter(f);
		writer.println(Date.from(Instant.ofEpochMilli(time))+" - ID : "+time+" - From: "+ request.getRemoteAddr());
		// dump headers
		writer.println(request.getRequestURL()+request.getQueryString());
	    Enumeration headerNames = request.getHeaderNames();
	    System.out.println("Headers:");
	    writer.println("Headers:");
	    while(headerNames.hasMoreElements()) {
	      String headerName = (String)headerNames.nextElement();
	      writer.println(headerName+":"+ request.getHeader(headerName));
	    }
	    BufferedReader test = request.getReader();
	    String l = test.readLine();
	    writer.println("Body:");
		while(l !=null){
			writer.println(l);
	    	l = test.readLine();
	    }
		logwriter.close();
		writer.close();
	}

	/**
	 * This should send the new data to the server somehow...
	 * 
	 * @param newData
	 */
	private void sendNewData(Map<String, String> newData) {
		String url = "";
		for (Map.Entry<String, String> entry : newData.entrySet()) {
			url = url + entry.getKey() + "=" + entry.getValue() + "&";
		}
		if (url.length() > 0)
			url = url.substring(0, url.length() - 1); // get rid of last &

		// how do i send this to server??
	}

	/**
	 * preprocess data for next part
	 * 
	 * @param data
	 * @return
	 */
	private Map<String, String> preprocess(HttpServletRequest request) {
		Enumeration<String> names = request.getParameterNames();
		Map<String, String> data = new HashMap<String, String>();
		// testing things
		while (names.hasMoreElements()) {
			String name = names.nextElement();
//			out.println(name);
//			out.println(request.getParameter(name));
//			out.println("<br/>");
			data.put(name, request.getParameter(name));
			System.out.println(name+":"+request.getParameter(name));
		}
		return data;
	}

	/**
	 * Pretends our thing is vulnerable to exploits
	 */
	private String evaluateExploit(String value) {
		String tmpvalue = new String(value);
		for(Rule r:rules){
			if(r.detect(tmpvalue)){
				tmpvalue = r.generateResponse(tmpvalue);
				detected = true;
			}
		}
		return tmpvalue;
	}







	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	public static void main(String[] args) throws IOException {
		// System.out.println(new HP().evaluateExploit("<hey im script>"));
		// System.out.println(new HP().evaluateExploit("1+1"));
		//System.out.println(new HP().detectCSRF("www.google.co.nz"));
		File f = new File("logs/"+5+".request");
		f.getParentFile().mkdirs();
		f.createNewFile();
		PrintWriter writer = new PrintWriter(f);
		writer.println("test");
		writer.close();
	}
}
