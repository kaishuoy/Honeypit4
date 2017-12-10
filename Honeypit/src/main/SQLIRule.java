package main;

import java.util.Random;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class SQLIRule extends Rule {
	String[] SQLI = new String[] { "+", "-", "/", "*", "AND", "OR", "||", "&&", "==", "===","'","UNION" };

	@Override
	public boolean detect(String input) {
		for (String str : SQLI) {
			if (input.contains(str)) {
				System.out.println("SQLI");
				return true;
			}
		}
		return false;
	}

	@Override
	public String generateResponse(String input) {
		input.replace("AND", "&&");
		input.replace("OR", "||");
		input.replace("===", "==");
		ScriptEngine se = new ScriptEngineManager()
				.getEngineByName("JavaScript");
		try {
			return "" + se.eval(input);
		} catch (ScriptException e) {
			Random rn = new Random();
			int line = 400+rn.nextInt(100);
			//return "Error: sql_get() expects parameter 1 to be resource, "
			//		+ "boolean given on line "+line+" .";
			return "The used SELECT statements have a different number of columns.";
		}
	}

	@Override
	public boolean flowthrough() {
		// TODO Auto-generated method stub
		return true;
	}
	
	public static void main(String[] args){
		
	}

}
