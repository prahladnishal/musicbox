import code
def fact(x):
	res = 1
	for i in range(1, x+1):
		res *= i
	return res

def C(n, r, M):
	num = fact(n)
	den = fact(r) * fact(n-r)
	res = num/den
	res = res % M
	return res

if __name__ == '__main__':
	c = code.InteractiveConsole(locals=locals())
	c.runcode('import readline')
	c.interact()

