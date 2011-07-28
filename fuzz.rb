#!/usr/bin/env ruby

require './rand.rb'
require './trace.rb'
require './eqfuncs.rb'
require 'metasm'

include Metasm


class FuzzMem < ApiHook

  def initialize(file,inp)

    $stderr.puts "tracing...\n\n"
    @bps = Trace.new(eqFuncsList,file,inp).owned

    raise "Sorry you haven't control any function arguments, cant fuzz..." if @bps.empty?

    @rnd = FuzzLib.new
    @dbg  = OS.current.create_debugger(file + " " + inp)
    @dbg.callback_exception = lambda {|s| rep_vuln s}
    @fuzz = {}
    @file = File.open(file + '.' + @dbg.pid.to_s + '.fuzz','wb')

    @dasm = AutoExe.decode_file(file).disassemble

    $stderr.puts "\n\n#{file}@#{@dbg.pid}: fuzzing ...\n"
    setup = @bps.map { |f| {:address => f[0], :condition => false}}
    ApiHook.new(@dbg,setup,lambda {|a| hook(a)},nil)
    File.unlink(@file.path) if @file.size == 0
    @file.close
    print "\n"
  end

  def rep_vuln(status)

    fbeg = @dasm.find_function_start(@fuzz[:addr])
    name = @dasm.label_alias[fbeg].first || fbeg
    i=1

    $stderr.puts "#### SIG#{status[:signal]} ####\n"
    case status[:signal]
      when "SEGV", "ABRT", "FPE", "ILL"
      then

        @file.puts "\nPid #{status[:status].pid} got SIG#{status[:signal]}! ;]\n"
        @file.puts "Fuzzed #{name}@#{fbeg.inspect} with\n"
        @fuzz[fbeg].each { |n,a|
          @file.puts "\targ_#{n}:\t#{a.inspect}\n"
        }
    end
  end

  def hook(args)
    fbeg = @dasm.find_function_start(@dbg.pc)
    @fuzz[fbeg] = []

    own = @bps[fbeg] || []
    own.each { |i|
      str = @rnd.rndFunc.call
      if a=alloc(str)
        @fuzz[:addr]=fbeg
        patch_arg(i,a) # one push after
        @dbg.sp = @dbg.resolve Expression[:esp,:-,str.length+1+8]
        @fuzz[fbeg] << [i,str]
      end

    }
  end


  ### treat @str@ as local variable to function
  def alloc(str)

    func = @dasm.function_at(@dbg.pc)
    return nil if func.nil? or func.return_address.nil?
    leave = false

    def is_end?(di)
      (leave = true; di.opcode.name =~ /^leave$/) or
      (di.opcode.name =~ /^pop$/ and  di.instruction.args[0].symbolic == :ebp and
      @dbg.di_at(di.address+1).opcode.name =~ /^ret$/)
    end

    def is_mov_ebp_esp?
      di = @dbg.di_at @dbg.pc
      fst,snd = @dbg.di_at(@dbg.pc).instruction.args.map { |a| a.symbolic}
      di.opcode.name =~ /^mov$/ and fst == :ebp and snd == :esp
    end

    def is_stack_align?
      di = @dbg.di_at @dbg.pc
      reg = @dbg.di_at(@dbg.pc).instruction.args.first.symbolic
      di.opcode.name =~ /^sub$/ and reg == :esp
    end

    ret = @dasm.block_including(func.return_address.first).list.find {
      |di| is_end?(di)
    }.address
    old_ebp = @dbg[:ebp]
    old_eip = @dbg.memory_read_int(@dbg.sp)
    @dbg.singlestep_wait until is_mov_ebp_esp?
    @dbg.singlestep_wait # one more ;]
    ebp  = @dbg[:ebp]

    @dbg.singlestep_wait until is_stack_align?
    loc_len = @dbg.resolve @dbg.di_at(@dbg.pc).instruction.args[1]

    addr = @dbg.sp-(4+loc_len+str.length+1)
    @dbg[addr,str.length+1] = str+"\x00"

    @dbg.bpx(ret,true) {
      @dbg.sp = ebp
    } if not leave
    return addr
  end

  ### find malloc adres based od libc offset
  ### TODO: how to use dl_resolve inside process?
  def find_malloc
    path,base = @dbg.modules.select{ |m| m.path.include? 'libc'}.
                 map{|m| [m.path,m.addr]}.first
    foo = AutoExe.decode_file(path)
    p foo.segments
    mall = foo.relocations.select { |r| r.symbol.name =~ /^malloc$/ }

    mall.each { |x| p x ; p foo.fileoff_to_addr(x.offset) }
    off = AutoExe.decode_file(path).module_symbols.select{ | x | x[0] == "malloc" }.first[1]

    p off
    base + off
  end

  ### deref malloc address from .got
  def deref_malloc

  end

  ## only x86-linux at this point
  def malloc(str)
    save_sp   =@dbg.get_reg_value(@dbg.register_sp)
    save_args =@dbg[save_sp,(@dbg.cpu.size/8)*2]
    oldpc =  @dbg.pc
    malloc_addr = deref_malloc || find_malloc
    eax = nil
    @dbg[save_sp,(@dbg.cpu.size/8)*2] = [oldpc,str.size+1].pack('V*')
    p @dbg.pc
    p malloc_addr
    @dbg.pc = malloc_addr
    @dbg.bpx(oldpc,true) {
      @dbg[save_sp,save_args.size] = save_args
      @dbg[:eax,str.size+1] = str+"\x00"

      eax = @dbg[:eax]
      raise 'Can not alloc space for fuzz string...' if eax == 0
    }
    p @dbg.pc
    @dbg.singlestep
    p @dbg.pc
    #p @dbg,di_at(@dbg.pc)
    sleep 1
    @dbg.continue_wait
    sleep 1
    p @dbg[:eip]
    p eax
    eax
  end

end

if __FILE__ == $0

  file = ARGV.shift || './a.out'
  inp  = ARGV.shift  || 'AAAA'
  FuzzMem.new(file,inp)

end
