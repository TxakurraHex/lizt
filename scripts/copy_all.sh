#!/usr/bin/env bash

HOME=/Users/gbasil/Projects/practicum/lizt/

rsync -avz --progress --exclude 'target/' --exclude '.*/' $HOME aws:/home/ubuntu/lizt/
