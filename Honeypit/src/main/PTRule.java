package main;

/**
 * Path traversal attack rule
 * 
 * https://en.wikipedia.org/wiki/Directory_traversal_attack
 * https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)
 * https://www.owasp.org/images/1/19/OTGv4.pdf
 * @author Kai
 *
 */
public class PTRule extends Rule {

	String[] PT = new String[] { "../","..","..\\","..%2f","%2e%2e%2f","%2e%2e/","%2e%2e%5c","%c1%1c","%c0%af",".php",".htm","/html" };



	String passwd = "root:!:0:0::/:/usr/bin/ksh\n" + "daemon:!:1:1::/etc:\n" + "bin:!:2:2::/bin:\n"
			+ "sys:!:3:3::/usr/sys: \n" + "adm:!:4:4::/var/adm:\n" + "uucp:!:5:5::/usr/lib/uucp: \n"
			+ "guest:!:100:100::/home/guest:\n" + "nobody:!:4294967294:4294967294::/:\n" + "lpd:!:9:4294967294::/:\n"
			+ "lp:*:11:11::/var/spool/lp:/bin/false \n" + "invscout:*:200:1::/var/adm/invscout:/usr/bin/ksh\n"
			+ "nuucp:*:6:5:uucp login user:/var/spool/uucppublic:/usr/sbin/uucp/uucico\n"
			+ "paul:!:201:1::/home/paul:/usr/bin/ksh\n" + "jdoe:*:202:1:John Doe:/home/jdoe:/usr/bin/ksh";
	@Override
	public boolean detect(String input) {
		for (String str : PT) {
			if (input.contains(str)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String generateResponse(String input) {

		return input; // should be a file error
	}

	public static void main(String[] args){
		System.out.println(new PTRule().detect("http://example.com/getUserProfile.jsp?item=../../../../etc/passwd"));
	}

	@Override
	public boolean flowthrough() {
		return false;
	}
}
