#!/usr/bin/env ruby
$LOAD_PATH << '.'
require 'octokit'
require 'sqlite3'
require 'fileutils'
require 'milestones'
require 'cwe'

include CWE

if ARGV.length != 3
	puts "Missing or invalid arguments: asvs.rb <project_name> <verification_level> <path_to_clone_repo>"
	puts "Example: asvs.rb asvs-graphql 2 /home/bobdobs/projects/"
	exit
end

project = ARGV[0]
project_level = ARGV[1]
repo_path = ARGV[2]

# create directory path from repo_path argument if it doesn't already exist
if not File.directory? repo_path
	FileUtils.mkdir_p repo_path
end

# docs - http://octokit.github.io/octokit.rb/Octokit/Client

ACCESS_TOKEN = ENV['GITHUB_PERSONAL_ACCESS_TOKEN']

client = Octokit::Client.new(:access_token => ACCESS_TOKEN)
client.auto_paginate = true

# connect to asvs.db
db = SQLite3::Database.new('asvs.db')

# create repository - http://octokit.github.io/octokit.rb/Octokit/Client/Repositories.html
puts "Creating repository..."
repository = client.create_repository(project)

# create milestones
milestones = {
	"Architecture, Design and Threat Modeling Verification Requirements" => "Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tAt1 components of the application are identified and have a reason for being in the app\r\n\r\n\tAt2 the architecture has been defined and the code adheres to the architecture\r\n\r\n\tAt3 the architecture and design is in place, in use, and effective",
	"Authentication Verification Requirements" => "Authentication is the act of establishing, or confirming, something (or someone) as authentic, that is, that claims made by or about the thing are true. Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tVerifies the digital identity of the sender of a communication.\r\n\r\n\tEnsures that only those authorised are able to authenticate and credentials are transported in a secure manner.",
	"Session Management Verification Requirements" => "One of the core components of any web-based application is the mechanism by which it controls and maintains the state for a user interacting with it. This is referred to this as Session Management and is defined asthe set of all controls governing state-full interaction between a user and the web-based application. Ensure that a verified application satisfies the following high level session management requirements:\r\n\r\n\tSessions are unique to each individual and cannot be guessed or shared.\r\n\r\n\tSessions are invalidated when no longer required and timed out during periods of inactivity.",
	"Access Control Verification Requirements" => "Authorization is the concept of allowing access to resources only to those permitted to use them. Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tPersons accessing resources holds valid credentials to do so.\r\n\r\n\tUsers are associated with a well-defined set of roles and privileges.\r\n\r\n\tRole and permission metadata is protected from replay or tampering.",
	"Validation, Sanitization and Encoding Verification Requirements" => "The most common web application security weakness is the failure to properly validate input coming from the client or from the environment before using it. This weakness leads to almost all of the major vulnerabilities in web applications, such as cross site scripting, SQL injection, interpreter injection, locale/Unicode attacks, file system attacks, and buffer overflows. Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tAll input is validated to be correct and fit for the intended purpose.\r\n\r\n\tData from an external entity or client should never be trusted and should be handled accordingly.",
	"Stored Cryptography Verification Requirements" => "Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tThat all cryptographic modules fail in a secure manner and that errors are handled correctly.\r\n\r\n\tThat a suitable random number generator is used when randomness is required.\r\n\r\n\tThat access to keys is managed in a secure way.",
	"Error Handling and Logging Verification Requirements" => "The primary objective of error handling and logging is to provide a useful reaction by the user, administrators, and incident response teams. The objective is not to create massive amounts of logs, but high quality logs, with more signal than discarded noise. High quality logs will often contain sensitive data, and must be protected as per local data privacy laws or directives. This should include:\r\n\r\n\tNot collecting or logging sensitive information if not specifically required.\r\n\r\n\tEnsuring all logged information is handled securely and protected as per its data classification.\r\n\r\n\tEnsuring that logs are not forever, but have an absolute lifetime that is as short as possible.\r\n\r\n\tIf logs contain private or sensitive data, the definition of which varies from country to country, the logs become some of the most sensitive information held by the application and thus very attractive to attackersin their own right.",
	"Data Protection Verification Requirements" => "There are three key elements to sound data protection: Confidentiality, Integrity and Availability (CIA). This standard assumes that data protection is enforced on a trusted system, such as a server, which has been hardened and has sufficient protections. The application has to assume that all user devices are compromised in some way. Where an application transmits or stores sensitive information on insecure devices, such as shared computers, phones and tablets, the application is responsible for ensuring data stored on these devices is encrypted and cannot be easily illicitly obtained, altered or disclosed. Ensure that a verified application satisfies the following high level data protection requirements:\r\n\r\n\tConfidentiality: Data should be protected from unauthorised observation or disclosure both in transit and when stored.\r\n\r\n\tIntegrity: Data should be protected being maliciously created, altered or deleted by unauthorizedattackers.\r\n\r\n\tAvailability: Data should be available to authorized users as required.",
	"Communications Verification Requirements" => "Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tThat TLS is used where sensitive data is transmitted.\r\n\r\n\tThat strong algorithms and ciphers are used at all times.",
	"Malicious Code Verification Requirements" => "Ensure that a verified application satisfies the following high level requirement:\r\n\r\n\tDetected malicious activity is handled securely and properly as to not affect the rest of the application.",
	"Business Logic Verification Requirements" => "Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tThe business logic flow is sequential and in order.",
	"Files and Resources Verification Requirements" => "Ensure that a verified application satisfies the following high level requirements:\r\n\r\n\tUntrusted file data should be handled accordingly and in a secure manner.\r\n\r\n\tObtained from untrusted sources are stored outside the webroot and limited permissions.",
	"API and Web Service Verification Requirements" => "Ensure that a verified application that uses RESTful or SOAP based web services has:\r\n\r\n\tadequate authentication, session management and authorization of all web services\r\n\r\n\tInput validation of all parameters that transit from a lower to higher trust level\r\n\r\n\tBasic interoperability of SOAP web services layer to promote API use",
	"Configuration Verification Requirements" => "Ensure that a verified application has:\r\n\r\n\tUp to date libraries and platform(s).\r\n\r\n\tA secure by default configuration.\r\n\r\n\tSufficient hardening that user initiated changes to default configuration do not unnecessarily expose or create security weaknesses or flaws to underlying systems."
}
puts "Creating milestones..."
milestones.each do | title, desc |
	client.create_milestone(repository.full_name, title, {:description => desc})
end

# create milestone hash with :title => milestone_id
milestones = {}
client.list_milestones(repository.id).each do | milestone |
	milestones[milestone.title] = milestone.number
end

# create issues
puts "Creating issues..."
issues = db.execute('SELECT * FROM ISSUES')
issue_metadata = {}
issues.each do | issue |
	issue_id = issue[0]
	issue_section = issue[1]
	issue_level = issue[2]
	issue_weight = issue[3]
	issue_cwe = issue[4]
	issue_milestone = issue[5]
	issue_title = issue[6]
	unless issue_cwe == "-1"
		cwe = CWE.const_get(issue_cwe.upcase)
		description = "For additional information on this requirement, see [#{cwe[:title]}](#{cwe[:link]})"
	else
		description = nil
	end
	issue = client.create_issue(repository.full_name, issue_title, description, {:milestone => issue_milestone.to_i <= project_level.to_i ? milestones[issue_milestone] : nil, :labels => "#{issue_section},#{issue_id},Level #{issue_level}"})
	issue_metadata[issue.id] = {} 
	issue_metadata[issue.id]["section"] = issue_section
	issue_metadata[issue.id]["level"] = issue_level
end

# create project boards and project cards
puts "Creating project boards..."
boards = db.execute('SELECT * FROM BOARDS')
boards.each do | board |
	section = board[0]
	title = board[1]
	milestone = board[2]
	project = client.create_project(repository.full_name, section + ' - ' + title, {:body => milestone})
	columns = ["Open", "Closed", "Level 1", "Level 2", "Level 3"]
	columns.each do | name |
		client.create_project_column(project.id, name)
	end
	column_label_map = {section => {}}
	project_columns = client.project_columns(project.id)
	project_columns.each do | column |
		column_label_map[section][column.name] = column.id
	end
	# create project cards for each board by label
	issue_metadata.each do | issue_id, issue_data |
		level = issue_data["level"]
		issue_section = issue_data["section"]
		if issue_section.eql? section
			case level
			when 1
				client.create_project_card(column_label_map[section]["Level 1"], content_id: issue_id, content_type: 'Issue')
			when 2
				client.create_project_card(column_label_map[section]["Level 2"], content_id: issue_id, content_type: 'Issue')
			when 3
				client.create_project_card(column_label_map[section]["Level 3"], content_id: issue_id, content_type: 'Issue')
			else
				puts "Not creating a board card"
			end
		end
	end
end

# map milestone titles to their URLs
project_milestones = client.milestones(repository.full_name)
milestones = {}
project_milestones.each do | milestone |
	milestones[milestone.title] = milestone.html_url
end

# change directory to repo_path
Dir.chdir repo_path
system("git clone #{repository.clone_url}")
Dir.chdir repo_path + repository.clone_url.split('/')[-1].split('.')[0]

readme_lines = ["[Architecture, Design and Threat Modeling Verification Requirements](#{milestones['Architecture, Design and Threat Modeling Verification Requirements']})\r\n\r\n",
                "[Authentication Verification Requirements](#{milestones['Authentication Verification Requirements']})\r\n\r\n",
                "[Session Management Verification Requirements](#{milestones['Session Management Verification Requirements']})\r\n\r\n",
                "[Access Control Verification Requirements](#{milestones['Access Control Verification Requirements']})\r\n\r\n",
                "[Validation, Sanitization and Encoding Verification Requirements](#{milestones['Validation, Sanitization and Encoding Verification Requirements']})\r\n\r\n",
                "[Stored Cryptography Verification Requirements](#{milestones['Stored Cryptography Verification Requirements']})\r\n\r\n",
                "[Error Handling and Logging Verification Requirements](#{milestones['Error Handling and Logging Verification Requirements']})\r\n\r\n",
                "[Data Protection Verification Requirements](#{milestones['Data Protection Verification Requirements']})\r\n\r\n",
                "[Communications Verification Requirements](#{milestones['Communications Verification Requirements']})\r\n\r\n",
                "[Malicious Code Verification Requirements](#{milestones['Malicious Code Verification Requirements']})\r\n\r\n",
                "[Business Logic Verification Requirements](#{milestones['Business Logic Verification Requirements']})\r\n\r\n",
                "[Files and Resources Verification Requirements](#{milestones['Files and Resources Verification Requirements']})\r\n\r\n",
                "[API and Web Service Verification Requirements](#{milestones['API and Web Service Verification Requirements']})\r\n\r\n",
                "[Configuration Verification Requirements](#{milestones['Configuration Verification Requirements']})\r\n\r\n"
        ]

File.open('README.md', 'w') do | f |
	readme_lines.each { |line| f.puts line }
end

system('git add README.md')
system('git commit -m "Initial commit"')
system('git push origin master')
print("Project is ready. Access it at: #{repository.html_url}\r\n")
