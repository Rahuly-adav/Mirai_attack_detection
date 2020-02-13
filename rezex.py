import re 
txt="hello world hey mskjvbsk vsjkdbvjsk svbsjvdbskbvs vnsv sjvjdsbv "
a=re.search(r"(?<=hey )\w+",txt)
print(a)

