package main;

public abstract class Rule {
	public abstract boolean detect(String input);
	public abstract String generateResponse(String input);
	public abstract boolean flowthrough();
}
