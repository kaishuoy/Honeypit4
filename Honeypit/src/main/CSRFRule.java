package main;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CSRFRule extends Rule {

	@Override
	public boolean detect(String input) {
		// https://stackoverflow.com/questions/5713558/detect-and-extract-url-from-a-string
		Pattern urlPattern = Pattern.compile(
				"(?:^|[\\W])((ht|f)tp(s?):\\/\\/|www\\.)" + "(([\\w\\-]+\\.){1,}?([\\w\\-.~]+\\/?)*"
						+ "[\\p{Alnum}.,%_=?&#\\-+()\\[\\]\\*$~@!:/{};']*)",
				Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
		Matcher matcher;
		String[] tokens = input.split("\\s+");
		for (String token : tokens) {
			matcher = urlPattern.matcher(token);
			if (matcher.matches())
				return true;
		}
		return false;
	}

	@Override
	public String generateResponse(String input) {
		return "Error 403. Unable to access page";
	}

	@Override
	public boolean flowthrough() {
		return false;
	}

}
