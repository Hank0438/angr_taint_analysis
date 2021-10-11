# angr_taint_analysis

## Project
https://starlabs.sg/blog/2021/08/identifying-bugs-in-router-firmware-at-scale-with-taint-analysis/
http://blog.k3170makan.com/2020/11/sporecrawler-binary-taint-analysis-with.html

## Problem
* Q: locate function by dataflow without symbol
  * argument
  * function return value or address  
* A: project.analyses.ReachingDefinitions