input = ['A', 'BAA/a.txt', 'AAA', 'B', 'C', 'A/A/', 'A/B', 'A/C', 'A/B/c.txt', 'A/B/a.txt' ]

if __name__ == '__main__':
	inputdepth = []
	for i in input:
		depth = i.count('/')
		inputdepth.append((depth, i))
	inputdepth.sort()
	print inputdepth

