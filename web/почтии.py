minn = 1000000

for q in range(1, 200):  
    q_2 = []
    q2 = bin(q)
    for i in q2[2:]:
        q_2.append(int(i))

    summ = 0
    for i in range(len(q_2)):
        summ += q_2[i]

    ost = summ % 2
    q_2.append(ost)

    summ = 0
    for i in range(len(q_2)):
        summ += q_2[i]

    ost = summ % 2
    q_2.append(ost)

    r = 0
    for i in range(len(q_2)):
        r = r * 2 + q_2[i]

    if r > 108 and r < minn:
        minn = r

print(minn)