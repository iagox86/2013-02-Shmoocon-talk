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

# TODO: ECB vs CBC
# TODO: Key re-use
# TODO: Bit-flipping
# TODO: Hash length extension
# TODO: Padding oracle example

# Use the same key/iv for all attacks
@@key = (1..32).map{rand(255).chr}.join
@@iv  = (1..32).map{rand(255).chr}.join

TEXT1 = "SkullSpace is a hackerspace in Winnipeg, founded December 2010. SkullSpace is a place for hackers, builders, programmers, artists, and anybody interested in how stuff works to gather in a common place and help focus their knowledge and creativity."
TEXT2 = "The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents. We live on a placid island of ignorance in the midst of black seas of infinity, and it was not meant that we should voyage far. The sciences, each straining in its own direction, have hitherto harmed us little; but some day the piecing together of dissociated knowledge will open up such terrifying vistas of reality, and of our frightful position therein, that we shall either go mad from the revelation or flee from the deadly light into the peace and safety of a new dark age."

def encrypt(text, mode)
  c = OpenSSL::Cipher::Cipher.new(mode)
  c.encrypt
  c.key = @@key
  c.iv  = @@iv
  encrypted = (c.update(text) + c.final).unpack("H*")

  
end

get('/') do
  puts("Hi")

<<EOF
<html>
  <body>
    Welcome to Ron's Shmoocon Demo! Please select an option:
    <ul>
      <li><a href='/ecb'>ECB vs CBC encryption</li>
      <li><a href='/bitflipping'>Bit-flipping</li>
      <li><a href='/keyreuse'>Key re-use</li>
      <li><a href='/lengthextension'>Hash length extension</li>
      <li><a href='/paddingoracle'>Padding oracle</li>
    </ul>
  </body>
</html>
EOF
end

get("/ecb") do
  if(params['data'].nil?)
    return <<EOF
<html>
  <body>
    <a href='/'>Back</a><p>
    <form method='get'>
      Encrypt the following text: <input type='text' name='data'><p>
      Using:<br>
      <input type='radio' name='mode' value='des-ecb'>DES-ECB<br>
      <input type='radio' name='mode' value='aes-256-cbc'>AES-256-CBC<br>
      <input type='submit' value='Submit'>
    </form>
  </body>
</html>
EOF

  end
end

