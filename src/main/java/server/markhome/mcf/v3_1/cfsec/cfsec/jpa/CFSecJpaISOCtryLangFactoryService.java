
// Description: Java 25 Factory service implementation for ISOCtryLang JPA objects

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	Java 25 Factory service implementation for ISOCtryLang JPA objects.
 */
public class CFSecJpaISOCtryLangFactoryService
    implements ICFSecISOCtryLangFactory
{
    public CFSecJpaISOCtryLangFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryLangPKey newPKey() {
        ICFSecISOCtryLangPKey pkey = new CFSecJpaISOCtryLangPKey();
        return( pkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLangPKey ensurePKey(ICFSecISOCtryLangPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryLangPKey) {
			return( (CFSecJpaISOCtryLangPKey)key );
		}
		else {
			CFSecJpaISOCtryLangPKey mapped = new CFSecJpaISOCtryLangPKey();
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			mapped.setRequiredISOLangId( key.getRequiredISOLangId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryLangHPKey newHPKey() {
        ICFSecISOCtryLangHPKey hpkey = new CFSecJpaISOCtryLangHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLangHPKey ensureHPKey(ICFSecISOCtryLangHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaISOCtryLangHPKey) {
			return( (CFSecJpaISOCtryLangHPKey)key );
		}
		else {
			CFSecJpaISOCtryLangHPKey mapped = new CFSecJpaISOCtryLangHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			mapped.setRequiredISOLangId( key.getRequiredISOLangId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryLangByCtryIdxKey newByCtryIdxKey() {
		ICFSecISOCtryLangByCtryIdxKey key = new CFSecJpaISOCtryLangByCtryIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLangByCtryIdxKey ensureByCtryIdxKey(ICFSecISOCtryLangByCtryIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryLangByCtryIdxKey) {
			return( (CFSecJpaISOCtryLangByCtryIdxKey)key );
		}
		else {
			CFSecJpaISOCtryLangByCtryIdxKey mapped = new CFSecJpaISOCtryLangByCtryIdxKey();
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryLangByLangIdxKey newByLangIdxKey() {
		ICFSecISOCtryLangByLangIdxKey key = new CFSecJpaISOCtryLangByLangIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLangByLangIdxKey ensureByLangIdxKey(ICFSecISOCtryLangByLangIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryLangByLangIdxKey) {
			return( (CFSecJpaISOCtryLangByLangIdxKey)key );
		}
		else {
			CFSecJpaISOCtryLangByLangIdxKey mapped = new CFSecJpaISOCtryLangByLangIdxKey();
			mapped.setRequiredISOLangId( key.getRequiredISOLangId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryLang newRec() {
        ICFSecISOCtryLang rec = new CFSecJpaISOCtryLang();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLang ensureRec(ICFSecISOCtryLang rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaISOCtryLang) {
			return( (CFSecJpaISOCtryLang)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecISOCtryLang.CLASS_CODE: {
					CFSecJpaISOCtryLang mapped = new CFSecJpaISOCtryLang();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecISOCtryLang",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecISOCtryLang");
			}
		}
	}

    @Override
    public ICFSecISOCtryLangH newHRec() {
        ICFSecISOCtryLangH hrec = new CFSecJpaISOCtryLangH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryLangH ensureHRec(ICFSecISOCtryLangH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaISOCtryLangH) {
			return( (CFSecJpaISOCtryLangH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecISOCtryLang.CLASS_CODE: {
					CFSecJpaISOCtryLangH mapped = new CFSecJpaISOCtryLangH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecISOCtryLang",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecISOCtryLang");
			}
		}
	}
}
