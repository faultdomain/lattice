#!/bin/bash
rsync -az --delete --exclude='.git' --exclude='target' ../lattice/ ubuntu@10.0.0.131:~/lattice/
