# picanha
<img width="750" height="1000" alt="image" src="https://github.com/user-attachments/assets/5c274ceb-52e5-4d29-ae64-d58bb9c84d1e" />

does lifting work when it's purely written by ai with coordination by someone who doesn't know what he's doing, but knows something about the lifting jumbo? maybe, and if not, it's just a few prompts away! (and you can always use IDA as an oracle)
tygoodshare^^

it has ui, and cli
to compile you need to put llvm/remill/rellic somewhere

it can decompile to C via rellic, lift functions to llvm with remill, it can automatically recompile target fuctnions with optimizations and pull their dependencies alongside them to lift as well
there are some errors (which is expected) because claude tried to patch remill/llvm which did not go well; i recommend not using the UI version unless you got some claude credits to burn (pull requests appreciated)
<img width="2560" height="1032" alt="image" src="https://github.com/user-attachments/assets/918ec98e-b32d-4e89-b56a-900b2dc4bf90" />

if you aren't sure how to build it, tell claude to build it and fix errors if any occur, should be ok
to not give all credit to claude, kimi k2.5 was used when my claude expired, since opencode can't use claude without credits, i stopped using it (claude code fucking sucks), but the chinese claude is kinda decent

it might lift jump tables, i told it to copy subgraph isomorphism and dag from code defender blog, it wrote some tests and they passed


warning: this repository is illegal as my remill license was revoked by @kyle-elliott-tob for terrible code
it is released as a protest towards these capitalistic practices and because i pushed it by accident and didn't notice the repo wasn't private and i cba

honorable mentions:
- @kyle-elliott-tob
- @gt853
- @llvm project
- @trailofbits (for remill/rellic)
- @anthropic for pasting this together with little intervention
- @hexrays which i copied layout images from to claude to attempt to inspire itself by it as much as possible (massive fail)
- @mrexodia and @brit (my #1 believers)
- @BELabs for keeping blare closed-source and making me pursue vibe alternatives and lying to myself about its quality
  @can1357 for vtil which is the og lifter
  @naci mergen and mergen community

  please do not open an issue for build issues, use your favorite llm and make a pull request. works on my machine 
  <img width="600" height="673" alt="image" src="https://github.com/user-attachments/assets/185ab78b-64c3-4114-9f73-c8beeed79786" />
