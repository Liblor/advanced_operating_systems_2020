import numpy as np
import matplotlib.pyplot as plt

# total time spend
BLOCKDRIVER_READ = "../measurements/blockdriver_read"
BLOCKDRIVER_WRITE = "../measurements/blockdriver_write"

# Waiting for device
BLOCKDRIVER_WAIT_READ = "../measurements/waiting_for_device_read"
BLOCKDRIVER_WAIT_WRITE = "../measurements/waiting_for_device_write"

# Waiting for irq flags
BLOCKDRIVER_IRQ_READ = "../measurements/read_irq_flag"
BLOCKDRIVER_IRQ_WRITE = "../measurements/write_irq_flag"


plt.rc('text', usetex=True)
plt.rc('font', family='serif')
plt.ioff()


def parse(file):
    with open(file) as f:
        lines = f.readlines()
    measurements = [int(i.split()[-1]) for i in lines]
    return measurements

bd_read = parse(BLOCKDRIVER_READ)
total_read = np.mean(bd_read)
std_read = np.std(bd_read)

bd_wait_read = parse(BLOCKDRIVER_WAIT_READ)
total_wait_read = np.mean(bd_wait_read)
std_wait_read = np.std(bd_wait_read)

bd_irq_read = parse(BLOCKDRIVER_IRQ_READ)
total_irq_read = np.mean(bd_irq_read)
std_irq_read = np.std(bd_irq_read)


bd_write = parse(BLOCKDRIVER_WRITE)
total_write = np.mean(bd_write)
std_write = np.std(bd_write)

bd_wait_write = parse(BLOCKDRIVER_WAIT_WRITE)
total_wait_write = np.mean(bd_wait_write)
std_wait_write = np.std(bd_wait_write)

bd_irq_write = parse(BLOCKDRIVER_IRQ_WRITE)
total_irq_write = np.mean(bd_irq_write)
std_irq_write = np.std(bd_irq_write)


p1 = plt.bar([1, 2], [total_read, total_write], 0.35)
p2 = plt.bar([1, 2], [total_wait_read, total_wait_write], 0.35)
#p3 = plt.bar([1, 2], [total_irq_read, total_irq_write], 0.35, bottom=[total_wait_read, total_wait_write])

plt.xticks([1, 2], ('Block Read', 'Block Write'))
plt.yticks(np.arange(0, 500222, 100000))
plt.ylabel("time in $\mu$s", ha="left", rotation=0, y=1.05)
plt.legend((p1[0], p2[0]), ('Total time', 'Waiting for device'))

plt.savefig("100-blockdriver_runtime.pdf", bbox_inches='tight')
