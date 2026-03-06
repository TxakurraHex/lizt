#!/usr/bin/env bash

HOME=/Users/gbasil/Projects/practicum/lizt/

rsync -avz --progress --exclude 'target/' --exclude '.*/' --exclude 'copy_all.sh' $HOME aws:/home/ubuntu/lizt/
