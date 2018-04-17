#ifndef HAX_CORE_EMULATE_OPS_H_
#define HAX_CORE_EMULATE_OPS_H_

/* Instruction handlers */
typedef void(em_handler_t)();
em_handler_t em_not;
em_handler_t em_neg;
em_handler_t em_inc;
em_handler_t em_dec;
em_handler_t em_add;
em_handler_t em_or;
em_handler_t em_adc;
em_handler_t em_sbb;
em_handler_t em_and;
em_handler_t em_sub;
em_handler_t em_xor;
em_handler_t em_test;
em_handler_t em_xadd;
em_handler_t em_cmp;
em_handler_t em_cmp_r;
em_handler_t em_bsf;
em_handler_t em_bsr;
em_handler_t em_bt;
em_handler_t em_bts;
em_handler_t em_btr;
em_handler_t em_btc;
em_handler_t em_rol;
em_handler_t em_ror;
em_handler_t em_rcl;
em_handler_t em_rcr;
em_handler_t em_shl;
em_handler_t em_shr;
em_handler_t em_sar;
em_handler_t em_bextr;
em_handler_t em_andn;

/* Dispatch handlers */
void fastop_dispatch(em_handler_t handler, void *src1, void *src2, void *dest, void *flags);

#endif /* HAX_CORE_EMULATE_OPS_H_ */
