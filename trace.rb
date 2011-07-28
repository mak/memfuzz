
require 'metasm'
require './apihook.rb'
include Metasm



class Integer
  def inspect
    "%Xh" % self
  end
end

module Metasm
 class Debugger
   def log(*a)
   end
 end
end


class Trace

  attr_reader :owned
  def initialize(eqFuncList,file,inp)
    @eqFuncList = eqFuncList
    @dbg = OS.current.create_debugger(file + " " + inp)
    @input = inp
    @dasm = AutoExe.decode_file(file).disassemble
    @funcList = find_functions
    @owned = {}
    setup = @funcList.map { |a| {:address => a, :condition => false}}
    ApiHook.new(@dbg,setup,lambda {|a| hook(a)},nil)
  end

  def find_functions
    @dasm.load_plugin 'dasm_all'
    @dasm.dasm_all_section '.text'
    @dasm.function.keys.select{ |x| x.kind_of? Integer}
  end

  def get_section_addr(name)
    @dasm.section_info.select { |n,a,l,i| name == n}.first[1]
  end


  def hook(args)
    @eqFuncList.each do |f|
      i =0
      owned_args  = []
      args.each do |x|
        i += 1
        b = case f
            when Symbol
              send f, @dbg,@dasm,@input,x
            when Proc
              f.call(@dbg,@dasm,@input,x)
            end
        owned_args << i if b
      end
      fbeg = @dasm.find_function_start(@dbg.pc)
      name = @dasm.label_alias[fbeg].first || fbeg
      $stderr.puts "\n#{name}@#{fbeg.inspect}:\n\tYou own: " + owned_args.map { |i| "[esp + #{i * @dbg.cpu.size/8}]"}.join(', ') + "\n\n" if not owned_args.empty?
      @owned[fbeg] = owned_args if not owned_args.empty?
    end
  end

end

if __FILE__ == $0

  file = ARGV.shift || './a.out'
  inp  = ARGV.shift  || 'AAAA'
  Trace.new(file,inp)

end

