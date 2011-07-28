require 'metasm'
require './trace'


src = <<EOS
int strcpy(char*, const char*);
int foo(char *a,char* b) __attribute__((export))
{
    strcpy(a,b);
}
int main(int argc, char **argv) __attribute__((export))
{
        char buf[256];
        if (argc < 2)
                return -6913;
        strcpy(buf, argv[1]);
        return 0;
}
EOS

Metasm::ELF.compile_c(Metasm::Ia32.new, src).encode_file('vuln_test')

eqFun = lambda {|dbg,dasm,inp,arg|
  dbg[arg,inp.size] == inp
}

Trace.new([eqFun],'./foo',"AAAA")
