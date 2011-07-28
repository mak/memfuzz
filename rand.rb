class FuzzLib

  def initialize
    @maxlibSize = 5000		#Max of 30000 bytes of fuzzing data
    @commonDelimiters = ["\x0a", "\x0d", ",", ".", ":", ";",
                         "&", "%", "\$", "\x20", "\x00", "#",
                         "(", ")", "{", "}", "<", ">", "\"",
                         "'", "\\", "|", "@", "*", "-"]

    @commonStrings = [ "\x41"*500,  "\x41"*1000, "\x41"*2000,
                       "\x41"*3000, "\x41"*4000, "\x41"*5000,
                        "\x41"*6000, "\x41"*7000, "\x41"*8000,
                       "\x41"*10000,"\x41"*11000,"\x41"*12000,
                       "~!@#\$^&"*1000,	"~!@#\$^&"*2000,
                       "~!@#\$^&"*3000,	"~!@#\$^&"*4000,
                       "~!@#\$^&"*5000,	"%n%n%n%n%n", "%p%p%p%p",
                       "%s"*500, "%x"*1000, "../"*1000,
                       "../"*5000, "%%20x", "%2e%2e/"*1000,
                       "16777215", "0x99999999", "0xffffffff",
                       "%u000", "AAAA"+"../"+"A"*300, "%"+"A"*3000]
    @prng = Random.new
  end

  def __rndSize
      @prng.rand(1...@maxlibSize)
  end

  def __rndList(list)
    i = @prng.rand(0...list.size)
    list.at(i)
  end

  def rndBinary
    @prng.bytes(__rndSize)
  end

  def rndAscii
    (1..__rndSize).map{|i| @prng.rand(65..90).chr}.join
  end


  def rndDelimiter
    common  + __rndList(@commonDelimiters) + common
  end

  def common
    __rndList(@commonStrings)
  end

  def rndFunc
    __rndList([lambda{common}, lambda{rndDelimiter}, lambda {rndAscii}, lambda { rndBinary }])
  end
end

