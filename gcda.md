# GCDA File Format

## Packet
```
version: u32 (special)
checksum: u32
elements: element*
```

## Element
```
tag: u32
length: u32
value: oneof(function, arcs, object_summary, program_summary)
```

## Function
- Can be length of 0, signifying nothing
```
id: u32
line_sum: u32
cfg_sum: u32 (if version >= 47)
```
- indicates that the given id is the new function id that other blocks fall under

## Arcs
- ignore if seen before first function
```
counter: counter (u64), repeated (length/2) times
```

## Object Summary
```
runcounts: u32
blank: u32
if length == 9 {
    actual_runcounts: u32
}
```

## Program Summary