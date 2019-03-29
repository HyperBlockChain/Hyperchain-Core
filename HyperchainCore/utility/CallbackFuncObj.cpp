//
////#include "CallbackFuncObj.h"
//
//
//template<typename pCallbackFunc>
//TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj()	: m_pCF(NULL)
//												, m_pCParam(NULL)
//{
//}
//
//template<typename pCallbackFunc>
//TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj(pCallbackFunc pCF, void* pCParam)	: m_pCF(pCF)
//																				, m_pCParam(pCParam)
//{
//}
//
//template<typename pCallbackFunc>
//TCallbackFuncObj<pCallbackFunc>::~TCallbackFuncObj()
//{
//}
//	
//template<typename pCallbackFunc>
//void TCallbackFuncObj<pCallbackFunc>::Set(pCallbackFunc pCF, void* pCParam)
//{
//	m_pCF		= pCF;
//	m_pCParam	= pCParam;
//}
//
//template<typename pCallbackFunc>
//pCallbackFunc TCallbackFuncObj<pCallbackFunc>::GetCallbackFunc()
//{
//	return m_pCF;
//}
//
//template<typename pCallbackFunc>
//void* TCallbackFuncObj<pCallbackFunc>::GetCallbackParam()
//{
//	return m_pCParam;
//}
//
//template<typename pCallbackFunc>
//TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj(const TCallbackFuncObj& crs)
//{
//	m_pCF = crs.m_pCF;
//	m_pCParam = crs.m_pCParam;		
//}
//
//template<typename pCallbackFunc>
//TCallbackFuncObj<pCallbackFunc>& TCallbackFuncObj<pCallbackFunc>::operator=(const TCallbackFuncObj& crs )
//{
//	if(&crs == this)	
//		return *this;
//
//	m_pCF		= crs.m_pCF;
//	m_pCParam	= crs.m_pCParam;
//	return *this;
//}
//
//
//
//
