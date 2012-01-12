#!/usr/bin/env ruby

require './rand.rb'
require './trace.rb'
require './eqfuncs.rb'
require 'metasm'

include Metasm

class MallocFail < RuntimeError
end

class String
  alias :len :length
end

class Bignum
  def hex; self.to_s(16)  end
end

class Fixnum
  def hex; self.to_s(16)  end
end


class FuzzMem < ApiHook

  attr_reader :bps, :dasm
  def initialize(file,inp,bps=nil,dasm=nil)

    $stderr.puts "tracing...\n\n"

    @dasm = dasm
    @dasm ||= AutoExe.decode_file(file).disassemble

    @bps = bps
    @bps ||= Trace.new(eqFuncsList,file,inp,@dasm).owned

    raise "Sorry you haven't control any function arguments, cant fuzz..." if @bps.empty?

    @rnd = FuzzLib.new
    @dbg  = OS.current.create_debugger(file + " " + inp)
    @dbg.callback_exception = lambda {|s| rep_vuln s}
    @fuzz = {}
    @file = File.open(File.expand_path(file + '.' + @dbg.pid.to_s + '.fuzz'),"wb")

    @ret_reg  = case @dbg.cpu.shortname
                  when 'x64'  then :rax
                  when 'ia32' then :eax
                  else raise 'unsupported arch'
                end

    @base_reg  = case @dbg.cpu.shortname
                  when 'x64'  then :rbp
                  when 'ia32' then :ebp
                  else raise 'unsupported arch'
                end


    @saved_ctx = {}

    $stderr.puts "\n\n#{file}@#{@dbg.pid}: fuzzing ...\n"
    setup = @bps.map { |f| {:address => f[0], :condition => false}}
    super(@dbg,setup,lambda {|a| hook(a)},nil)
    ### jizaz ruby api suck so hard...
    begin
      File.unlink(@file.path) if @file.size == 0
    rescue
      File.unlink(@file.path) if File.size(@file.path) == 0
    end
    @file.close
    print "\n"
  end

  def rep_vuln(status)

    $stderr.puts "\n#### SIG#{status[:signal]} ####\n"
    case status[:signal]
      when "SEGV", "ABRT", "FPE", "ILL"
      then
        @file.puts @dbg.di_at @dbg.pc
        @file.puts "\nPid #{status[:status].pid} got SIG#{status[:signal]}! ;]\n"
        @fuzz.each { |fbeg,store|
          name = (@dasm.label_alias[fbeg] || [fbeg]).first
          @file.puts "Fuzzed #{name}@#{fbeg.inspect} with\n"
          store[:fuzz].each { |n,a|
            @file.puts "\targ_#{n}:\t#{a.inspect}\n"
          }
        }
        stacktrace
        @file.puts @dbg.ctx.do_getregs
        @file.flush
    end
  end

  def stacktrace
    @file.puts "\nBacktrace: "
    @dbg.stacktrace.reverse { |a,n| @file.puts "#{n}@#{a.hex}" }
  end

  def hook(args)

    fbeg = @dasm.find_function_start(@dbg.pc) #.instruction.args)
    @fuzz[fbeg] ||= {}
    @fuzz[fbeg][:alloc] ||= []
    @fuzz[fbeg][:fuzz] ||= []

    if not @fuzz[fbeg][:alloc].empty?
      @fuzz[fbeg][:alloc].each { |i,str|
        ret = @dbg.func_retval
        $stderr.puts "malloc ret: #{ret.hex}"
        @dbg[ret,str.len] = str

        @dbg.ctx.do_setregs @saved_ctx[fbeg]
        @saved_ctx.delete fbeg

        patch_arg(i-1,ret)
        @fuzz[fbeg][:fuzz] << [i,str]
      }

    else
      (@bps[fbeg] || []).each do |i|
        str = @rnd.rndFunc[].to_s

        @saved_ctx[fbeg] = @dbg.ctx.do_getregs

        alloc(str)
        @fuzz[fbeg][:alloc] << [i,str]
      end
    end

  end


  ### treat @str@ as local variable to function
  def alloc(str)

    # func = @dasm.function_at(@dbg.pc)
    # return nil if func.nil? or func.return_address.nil?
    # leave = false

    # def is_end?(di)
    #   (leave = true; di.opcode.name =~ /^leave$/) or
    #   (di.opcode.name =~ /^pop$/ and  di.instruction.args[0].symbolic == :ebp and
    #   @dbg.di_at(di.address+1).opcode.name =~ /^ret$/)
    # end

    # def is_mov_ebp_esp?
    #   di = @dbg.di_at @dbg.pc
    #   fst,snd = @dbg.di_at(@dbg.pc).instruction.args.map { |a| a.symbolic}
    #   di.opcode.name =~ /^mov$/ and fst == @base_reg and snd == @dbg.register_sp
    # end

    # def is_stack_align?
    #   di = @dbg.di_at @dbg.pc
    #   reg = @dbg.di_at(@dbg.pc).instruction.args.first.symbolic
    #   di.opcode.name =~ /^sub$/ and reg == @dbg.register_sp
    # end

    str << "\x00" if str[-1] != "\x00"
    malloc(str)
  end

  def find_libc
    mc = @dbg.modules.find { |m| m.path =~ /^\/lib.*\/libc/}
    return [mc.addr,mc.path]
  end

  ### find malloc adres based od libc offset
  def find_malloc
    base,path = find_libc
    bin = AutoExe.decode_file(path)
    off = bin.label_addr('malloc')
    return (off > base ? off : base + off)
  end

  ### deref malloc address from .got
  def deref_malloc
    bin = AutoExe.decode_file("/proc/#{@dbg.pid}/exe")
    if got = bin.relocations.find {|r| r.symbol.name == /^malloc$/ }
      base,path = find_libc
      a = got.offset
      return ( a > base ? a : @dbg.memory_read_int(a) )
    end
    return nil
  end

  def push_arg(arg,n=0)
    case @dbg.cpu.shortname
      when 'ia32' then @dbg.sp -= 4 ; @dbg[@dbg.sp,4] = [arg].pack('V')
      when 'x64'  then @dbg.func_arg_set(n,arg)
    else raise 'unsupported arch'
    end
  end

  ## only x86-linux at this point
  def malloc(str)
    malloc_addr = find_malloc
    $stderr.puts "[*] hooking call to malloc@#{malloc_addr.hex} ret: #{@dbg.pc.hex}"

    @dbg.sp -= @dbg.cpu.size / 8
    push_arg(str.len)
    @dbg.func_retaddr_set(@dbg.pc)
    @dbg.pc  = malloc_addr
  end

end

if __FILE__ == $0

  file = ARGV.shift || './a.out'
  inp  = ARGV.shift  || 'AAAA'
  bps = dasm = nil
  while true
    x = FuzzMem.new(file,inp,bps,dasm)
    bps ||= x.bps
    dasm ||= x.dasm
  end

end
