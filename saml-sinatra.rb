require 'rubygems'
require 'sinatra'

# Include all of the required java libs
Dir.glob(File.join(File.dirname(__FILE__), 'java/asf/lib/*.jar')).each {|f| require f }

# require saml manager jar
Dir.glob(File.join(File.dirname(__FILE__), 'java/asf/dist/*.jar')).each {|f| require f }

set :port, 7700

PARTNER_ID = 'p0000280'
KEYSTORE_PASSWORD = 'alltel123'
CERT_FILE = "config/certs/saml/production/#{PARTNER_ID}.p12"

get '/saml/cert' do
	s_mgr = com.alltel.saml.SamlManager.new
	s_mgr.setKeyStoreFile(CERT_FILE)
	s_mgr.setKeyStorePassword(KEYSTORE_PASSWORD)
	s_mgr.setKeyEntryPassword(KEYSTORE_PASSWORD)
	
	s_mgr.getSamlAssertionXml
end
