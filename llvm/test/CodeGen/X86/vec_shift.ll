; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-unknown -mattr=+sse2 | FileCheck %s --check-prefix=X32
; RUN: llc < %s -mtriple=x86_64-unknown -mattr=+sse2 | FileCheck %s --check-prefix=X64

define <2 x i64> @t1(<2 x i64> %b1, <2 x i64> %c) nounwind  {
; X32-LABEL: t1:
; X32:       # %bb.0: # %entry
; X32-NEXT:    psllw %xmm1, %xmm0
; X32-NEXT:    retl
;
; X64-LABEL: t1:
; X64:       # %bb.0: # %entry
; X64-NEXT:    psllw %xmm1, %xmm0
; X64-NEXT:    retq
entry:
	%tmp6 = bitcast <2 x i64> %c to <8 x i16>		; <<8 x i16>> [#uses=1]
	%tmp8 = bitcast <2 x i64> %b1 to <8 x i16>		; <<8 x i16>> [#uses=1]
	%tmp9 = tail call <8 x i16> @llvm.x86.sse2.psll.w( <8 x i16> %tmp8, <8 x i16> %tmp6 ) nounwind readnone 		; <<8 x i16>> [#uses=1]
	%tmp10 = bitcast <8 x i16> %tmp9 to <2 x i64>		; <<2 x i64>> [#uses=1]
	ret <2 x i64> %tmp10
}

define <2 x i64> @t3(<2 x i64> %b1, i32 %c) nounwind  {
; X32-LABEL: t3:
; X32:       # %bb.0: # %entry
; X32-NEXT:    movd {{.*#+}} xmm1 = mem[0],zero,zero,zero
; X32-NEXT:    psraw %xmm1, %xmm0
; X32-NEXT:    retl
;
; X64-LABEL: t3:
; X64:       # %bb.0: # %entry
; X64-NEXT:    movd %edi, %xmm1
; X64-NEXT:    psraw %xmm1, %xmm0
; X64-NEXT:    retq
entry:
	%tmp2 = bitcast <2 x i64> %b1 to <8 x i16>		; <<8 x i16>> [#uses=1]
	%tmp4 = insertelement <4 x i32> undef, i32 %c, i32 0		; <<4 x i32>> [#uses=1]
	%tmp8 = bitcast <4 x i32> %tmp4 to <8 x i16>		; <<8 x i16>> [#uses=1]
	%tmp9 = tail call <8 x i16> @llvm.x86.sse2.psra.w( <8 x i16> %tmp2, <8 x i16> %tmp8 )		; <<8 x i16>> [#uses=1]
	%tmp11 = bitcast <8 x i16> %tmp9 to <2 x i64>		; <<2 x i64>> [#uses=1]
	ret <2 x i64> %tmp11
}

declare <8 x i16> @llvm.x86.sse2.psra.w(<8 x i16>, <8 x i16>) nounwind readnone

define <2 x i64> @t2(<2 x i64> %b1, <2 x i64> %c) nounwind  {
; X32-LABEL: t2:
; X32:       # %bb.0: # %entry
; X32-NEXT:    psrlq %xmm1, %xmm0
; X32-NEXT:    retl
;
; X64-LABEL: t2:
; X64:       # %bb.0: # %entry
; X64-NEXT:    psrlq %xmm1, %xmm0
; X64-NEXT:    retq
entry:
	%tmp9 = tail call <2 x i64> @llvm.x86.sse2.psrl.q( <2 x i64> %b1, <2 x i64> %c ) nounwind readnone 		; <<2 x i64>> [#uses=1]
	ret <2 x i64> %tmp9
}

declare <2 x i64> @llvm.x86.sse2.psrl.q(<2 x i64>, <2 x i64>) nounwind readnone

declare <8 x i16> @llvm.x86.sse2.psll.w(<8 x i16>, <8 x i16>) nounwind readnone
