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

/**
 * Implementation of Honeypit using Java Servlet class
 * 
 * The honeypit is not vulnerable to common web based attacks, nor
 * does it contain useful data. Attackers attempting to break into
 * the honeypit will see apparent weaknesses which they will attempt
 * to exploit
 */
@WebServlet("/HP")
public class HP extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	
	// global tracker for whether or not an attack attemp has happened
	private static boolean detected;
	private List<Rule> rules = new ArrayList<Rule>();
	// defines what rules should be activated in what circumstance
	private boolean[][] activation;

	public HP() {
		super();
		// add more rules here as required
		rules.add(new PTRule());
		rules.add(new PT2Rule());
		rules.add(new XSSRule());
		rules.add(new SQLIRule());
		activate();
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
				
		// preprocess data into a more usable form
		detected = false;
		Map<String, String> data = preprocess(request);
		Map<String, String> newData = new HashMap<String, String>();
		for (Map.Entry<String, String> ent : data.entrySet()) {
			for(int i=0;i<rules.size();i++){
				// should we use or ignore this rule?
				if(activatedRule(i,request.getRemoteAddr())){
					Rule r = rules.get(i);
					// attack detected, stop now
					if(r.detect(ent.getValue())){
						detected = true;
						newData.put(ent.getKey(), r.generateResponse(ent.getValue()));
						break;
					}
				}
			}
		}
		out.println("post processing<br/>");
		for (Map.Entry<String, String> ent : newData.entrySet()) {
			out.println(ent.getKey() + " " + ent.getValue());
			out.println("<br/>");
		}
		// log if we found an attacker
		if(detected){
			System.out.println("detected");
			logRequest(request,ct);
		}
	}

	/**
	 * generates the initial activation grid according to number
	 * of exploit detection rules loaded.
	 * 
	 * number of possible exploit combinations is:
	 *     (number of exploits)! - 1
	 * as we are not interested in case where all exploits ignored
	 */
	private void activate(){
		// calculate number of valid combos
		int validCombos = 1;
		for(int i=rules.size();i>0;i--){
			validCombos = validCombos*2;
		}
		// generate activation array
		activation = new boolean[validCombos][rules.size()];
		
		for(int i=1;i<validCombos;i++){
			// convert combo key to binary
			// ex. 7 => 111
			String booleanRep = Integer.toBinaryString(i);
			// pad boolean representation with 0's if required
			if(booleanRep.length()<rules.size()){
				booleanRep = String.format("%"+(rules.size()-booleanRep.length())+"s"," ")+booleanRep;
			}
			// input boolean representation into array
			for(int j=booleanRep.length()-1;j>=0;j--){
				if(booleanRep.charAt(j)=='1')
					activation[i-1][j] = true;
				else
					activation[i-1][j] = false;
			}
		}
	}
	
	/**
	 * Determines if a given rule should be activated or not given
	 *	the atttacking ip address and the rule's key(number in
	 *	rules list)
	 */
	private boolean activatedRule(int ruleKey, String ip){
		// convert ip address into single long
		System.out.println(ip);
		long realip = Long.parseLong(ip.replace(".",""));
		// calculate remainder
		int rm = (int) (realip%activation.length);
		return activation[rm][ruleKey];
	}
	
	/**
	 * Records an attack attempt in logging system for future 
	 * analysis
	 */
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
	 * Preprocess data by converting a request into a Map of 
	 * request parameter name to request parameter value
	 * this makes the data much easier to process later on
	 */
	private Map<String, String> preprocess(HttpServletRequest request) {
		Enumeration<String> names = request.getParameterNames();
		Map<String, String> data = new HashMap<String, String>();
		// testing things
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			data.put(name, request.getParameter(name));
		}
		return data;
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

	// tests things, doesnt do much other things
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
