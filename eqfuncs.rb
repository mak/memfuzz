

## x86 only
def string_eq (dbg,dasm,inp,arg)
  mem =   dbg[arg,inp.size]
  mem == inp
end

def string_size(dbg,dasm,inp,arg)
  #just guessing
  arg == inp.size
end

def string_contain(dbg,dasm,inp,arg)
  str = "";tmp=nil;i=0;
  while tmp != 0
    str << dbg[arg+i,1]
    i+=1
  end
  str.include? inp
end


def eqFuncsList
#  [:string_contain,:string_size,:string_eq]
  [:string_eq]
end
