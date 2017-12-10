package main;

public class XSSRule extends Rule {
	String[] XSS = new String[] { "<script>", "</script>", "<img>","</img>","%3Cscript%3E"};
	public boolean detect(String input) {
		for (String str : XSS) {
			if (input.contains(str))
				return true;
		}
		int lefties = 0;
		int righties = 0;
		for (int i = 0; i < input.length(); i++) {
			if (input.charAt(i) == ('<'))
				lefties++;
			else if (input.charAt(i) == ('>'))
				righties++;
		}
		if (lefties > 0 && lefties == righties) {
			System.out.println("XSS");
			return true;
		}
		return false; // no xss
	}

	public String generateResponse(String input) {
		int leftmax = 0;
		int rightmax = 0;
		for (int i = 0; i < input.length(); i++) {
			if (input.charAt(i) == '<') {
				leftmax = i;
				break;
			}
		}
		for (int i = input.length() - 1; i > 0; i--) {
			if (input.charAt(i) == '>') {
				rightmax = i;
				break;
			}
		}
		String script = input.substring(leftmax, rightmax + 1);
		// maybe write this back into response? TODO
		return script;
	}

	@Override
	public boolean flowthrough() {
		return false;
	}
}
