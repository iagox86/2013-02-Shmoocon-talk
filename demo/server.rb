$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

##
# RemoteTestServer
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple application that is vulnerable to a ECB chosen prefix attack.
##

require 'openssl'
require 'sinatra'

set :port, 20222

# Use the same key/iv for all attacks
@@key = (1..32).map{rand(255).chr}.join
#@@iv  = (1..32).map{rand(255).chr}.join

TEXT1 = "SkullSpace is a hackerspace in Winnipeg, founded December 2010. SkullSpace is a place for hackers, builders, programmers, artists, and anybody interested in how stuff works to gather in a common place and help focus their knowledge and creativity."
TEXT2 = "The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents. We live on a placid island of ignorance in the midst of black seas of infinity, and it was not meant that we should voyage far. The sciences, each straining in its own direction, have hitherto harmed us little; but some day the piecing together of dissociated knowledge will open up such terrifying vistas of reality, and of our frightful position therein, that we shall either go mad from the revelation or flee from the deadly light into the peace and safety of a new dark age."

def sanitize(str)
  str2 = ''

  str.bytes.each do |b|
    if(b >= 0x20 && b <= 0x7F)
      str2 = str2 + b.chr
    else
      str2 = str2 + ("\\x%02x" % b)
    end
  end

  return str2
end

def unsanitize(str)
  state = ' '
  result = ''
  first = ''
  str.chars.each do |c|
    case state
    when ' '
      #puts("state = ' '")
      if(c == '\\')
        state = '\\'
      else
        result = result + c
      end
    when '\\'
      #puts("state = '\\'")
      if(c == 'x')
        state = 'x'
      else
        result = result + '\\' + c
        state = ' '
      end
    when 'x'
      #puts("state = 'x'")
      if(c =~ /[\dabcdef]/)
        first = c
        state = '#'
      else
        result = result + '\\x' + c
        state = ' '
      end
    when '#'
      #puts("state = '#'")
      if(c =~ /[\dabcdef]/)
        result = result + [first + c].pack('H*')
      else
        result = result + '\\x' + first + c
      end
      state = ' '
    end
  end

  return result
end

def encrypt(text, mode, split_blocks)
  c = OpenSSL::Cipher::Cipher.new(mode)
  c.encrypt
  c.key = @@key
#  c.iv  = @@iv
  encrypted = (c.update(text) + c.final)

  result = "<!-- Make the encrypted data easy for the demo -->\n\n"
  result = "<!-- [[[#{encrypted.unpack("H*").first}]]] -->\n\n"

  if(split_blocks)
    result += "<table border='1'>\n"
    result += "  <tr>\n"
    result += "    <td>Block</td>\n"
    result += "    <td>Encrypted</td>\n"
    result += "    <td>Plaintext</td>\n"
    result += "  </tr>\n"
    1.upto(encrypted.length / c.block_size) do |i|
      block = encrypted[(i - 1) * c.block_size, c.block_size]
      plain = text[(i - 1) * c.block_size, c.block_size]
      result += "  <tr>\n"
      result += "    <td>Block #{i}: </td>\n"
      result += "    <td><tt>#{block.unpack("H*")}</tt></td>\n"
      #result += "    <td><tt>#{sanitize(block)}</tt></td>\n"
      result += "    <td><tt>#{sanitize(plain)}</tt></td>\n"
      result += "  </tr>\n"
    end
    result += "</table>\n"
  else
    result += "<table border='1'>\n"
    result += "  <tr>\n"
    result += "    <td><tt>#{encrypted.unpack("H*")}</tt></td>\n"
    result += "    <td><tt>#{sanitize(encrypted)}</tt></td>\n"
    result += "  </tr>\n"
    result += "</table>\n"
  end

  return result
end

get('/') do
<<EOF
<html>
  <body>
    Welcome to Ron's Shmoocon Demo! Please select an option:
    <ul>
      <li><a href='/ecb'>ECB vs CBC encryption</li>
      <li><a href='/keyreuse'>Key re-use</li>
      <li><a href='/lengthextension'>Hash length extension</li>
      <li><a href='/paddingoracle'>Padding oracle</li>
    </ul>
  </body>
</html>
EOF
end

get("/ecb") do
  result = "<a href='/'>Home</a><p>"

  if(params['data'].nil?)
    result += <<EOF
      <form method='get'>
        Encrypt the following text: <input type='text' name='data' value='#{params['data'].nil? ? '' : params['data']}' size=100><br>
        <input type='submit' value='Submit'>
      </form>
EOF
  else
    result += <<EOF
      Encrypted with AES-128-ECB:<br>
      #{encrypt(params['data'], "AES-128-ECB", true)}<p>
      Encrypted with AES-128-CBC:<br>
      #{encrypt(params['data'], "AES-128-CBC", true)}<p>
EOF
  end

  return result
end

get("/keyreuse") do
  result = "<a href='/'>Home</a><p>"

  result += <<EOF
    <form method='get'>
      Please specify a prefix: <input type='text' name='data' value='#{params['data'].nil? ? '' : params['data']}' size=100><br>
      Note: Must be in hex (eg, '41414141...')<br>
      (Some 'secret' text will be appended before encryption!)<p>
      Please choose an encryption mode, too:<br>
      <input type='radio' name='mode' value='des-ecb' #{params['mode'] == 'des-ecb' ? "checked" : ""}>des-ecb<br>
      <input type='radio' name='mode' value='aes-128-cbc' #{params['mode'] == 'aes-128-cbc' ? "checked" : ""}>aes-128-cbc<br>
      <input type='radio' name='mode' value='aes-256-ctr' #{params['mode'] == 'aes-256-ctr' ? "checked" : ""}>aes-256-ctr<br>
      <input type='submit' value='Submit'>
    </form>
EOF
  if(!params['data'].nil?)
    data = [params['data']].pack('H*')
    result += <<EOF
      The result of encrypt("#{params['mode']}", "#{params['data']}" || TEXT1):
      #{encrypt(data + TEXT1, params['mode'], true)}<p>
EOF
  end

  return result
end

get("/lengthextension") do
  SECRET = "MySecretString"
  DATA   = "action=read_file&file=somethingboring"

  result = "<a href='/'>Home</a><p>"

  result += <<EOF
    You've captured a packet with the following data:<br>
    <ul>
      <li>Signature = <tt>#{Digest::MD5.hexdigest(SECRET + DATA)}</tt></li>
      <li>Data = <tt>#{DATA}</tt></li>
      <li>Secret length = <tt>#{SECRET.length}</tt></li>
    </ul>

    The Signature is calculated as, <tt>MD5(SECRET || "#{DATA}")</tt>.<p>

    Your mission is to append a different filename, and also to determine a valid signature for that data.

    <form method='get'>
      New signature: <input type='text' name='signature' size=50 value='#{params['signature'].nil? ? '' : params['signature']}'><br>
      (Note: Please provide the signature as a hex string (eg, 1a2b3c...)<p>

      New data: <input type='text' name='data' value='#{params['data'].nil? ? '' : params['data']}' size=100><br>
      (Note: c-style hex escapes (eg, "\\x00") are accepted in the data)<p>
      <input type='submit' value='Submit'>
    </form>
EOF
  if(!params['data'].nil?)
    data = unsanitize(params['data'])

    goodsignature = Digest::MD5.hexdigest(SECRET + data)
    if(goodsignature == params['signature'])
      result += "THE RESULT OF YOUR ATTEMPT: <font color='green'>SUCCESS</font><p>"
    else
      result += "THE RESULT OF YOUR ATTEMPT: <font color='red'>FAILURE</font><p>"
    end

    result += <<EOF
      <tt>MD5(SECRET || "#{sanitize(data)}") = <b>#{goodsignature}</b></tt><p>
      You guessed: <tt><b>#{params['signature']}</b></tt>
EOF
  end

  return result
end

get("/paddingoracle") do
  result = "<a href='/'>Home</a><p>"

  c = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
  c.encrypt
  c.key = @@key
  encrypted = (c.update(TEXT2) + c.final)

  if(!params['data'].nil?)
    data = [params['data']].pack("H*")
    success = nil
    begin
      c = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
      c.decrypt
      c.key = @@key
      c.update(data)
      c.final
      success = true
    rescue OpenSSL::Cipher::CipherError
      success = false
    end
    result += "The result of <tt>decrypt(\"#{data.unpack("H*")}\")</tt>:<br>"
    if(success)
      result += "THE RESULT OF YOUR ATTEMPT: <font color='green'>SUCCESS</font><p>"
    else
      result += "THE RESULT OF YOUR ATTEMPT: <font color='red'>FAILURE</font><p>"
    end
  end

  result += <<EOF
    <form method='get'>
      Attempt to secretly decrypt the following data:<br>
      <input type='text' name='data' size=100 value='#{params['data'].nil? ? encrypted.unpack("H*").pop : params['data']}'><br>
      <input type='submit' value='Submit'>
    </form>

  Here's a string encrypted in AES-256-CBC:<p>
  #{encrypt(TEXT2, "AES-256-CBC", true)}
EOF

  return result
end
