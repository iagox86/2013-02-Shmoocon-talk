##
# RemoteTestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
##
#
require 'httparty'

require './prephixer/Prephixer'

class ShmooconTestModule
  attr_reader :iv, :data

  NAME = "RemoteTestModule(tm)"

  def initialize()
    @data = HTTParty.get("http://localhost:20222/keyreuse?data=&mode=aes-128-cbc").parsed_response
    @data.gsub!(/.*\[\[\[/m, '')
    @data.gsub!(/\]\]\].*/m, '')
    puts("Data: #{@data}")
    @data = [@data].pack("H*")
    @iv = nil
  end

  def encrypt_with_prefix(prefix)
    result = HTTParty.get("http://localhost:20222/keyreuse?&mode=aes-128-cbc&data=#{prefix.unpack("H*").first}")
    result = result.parsed_response
    result.gsub!(/.*\[\[\[/m, '')
    result.gsub!(/\]\]\].*/m, '')

    return [result].pack("H*")
  end
end

begin
  mod = ShmooconTestModule.new
  puts Prephixer.decrypt(mod, true, true)
rescue Errno::ECONNREFUSED => e
  puts(e.class)
  puts("Couldn't connect to remote server: #{e}")
end

