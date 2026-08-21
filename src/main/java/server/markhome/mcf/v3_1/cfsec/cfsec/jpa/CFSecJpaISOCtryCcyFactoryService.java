
// Description: Java 25 Factory service implementation for ISOCtryCcy JPA objects

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
 *	Java 25 Factory service implementation for ISOCtryCcy JPA objects.
 */
public class CFSecJpaISOCtryCcyFactoryService
    implements ICFSecISOCtryCcyFactory
{
    public CFSecJpaISOCtryCcyFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryCcyPKey newPKey() {
        ICFSecISOCtryCcyPKey pkey = new CFSecJpaISOCtryCcyPKey();
        return( pkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcyPKey ensurePKey(ICFSecISOCtryCcyPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryCcyPKey) {
			return( (CFSecJpaISOCtryCcyPKey)key );
		}
		else {
			CFSecJpaISOCtryCcyPKey mapped = new CFSecJpaISOCtryCcyPKey();
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			mapped.setRequiredISOCcyId( key.getRequiredISOCcyId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryCcyHPKey newHPKey() {
        ICFSecISOCtryCcyHPKey hpkey = new CFSecJpaISOCtryCcyHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcyHPKey ensureHPKey(ICFSecISOCtryCcyHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaISOCtryCcyHPKey) {
			return( (CFSecJpaISOCtryCcyHPKey)key );
		}
		else {
			CFSecJpaISOCtryCcyHPKey mapped = new CFSecJpaISOCtryCcyHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			mapped.setRequiredISOCcyId( key.getRequiredISOCcyId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryCcyByCtryIdxKey newByCtryIdxKey() {
		ICFSecISOCtryCcyByCtryIdxKey key = new CFSecJpaISOCtryCcyByCtryIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcyByCtryIdxKey ensureByCtryIdxKey(ICFSecISOCtryCcyByCtryIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryCcyByCtryIdxKey) {
			return( (CFSecJpaISOCtryCcyByCtryIdxKey)key );
		}
		else {
			CFSecJpaISOCtryCcyByCtryIdxKey mapped = new CFSecJpaISOCtryCcyByCtryIdxKey();
			mapped.setRequiredISOCtryId( key.getRequiredISOCtryId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryCcyByCcyIdxKey newByCcyIdxKey() {
		ICFSecISOCtryCcyByCcyIdxKey key = new CFSecJpaISOCtryCcyByCcyIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcyByCcyIdxKey ensureByCcyIdxKey(ICFSecISOCtryCcyByCcyIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaISOCtryCcyByCcyIdxKey) {
			return( (CFSecJpaISOCtryCcyByCcyIdxKey)key );
		}
		else {
			CFSecJpaISOCtryCcyByCcyIdxKey mapped = new CFSecJpaISOCtryCcyByCcyIdxKey();
			mapped.setRequiredISOCcyId( key.getRequiredISOCcyId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecISOCtryCcy newRec() {
        ICFSecISOCtryCcy rec = new CFSecJpaISOCtryCcy();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcy ensureRec(ICFSecISOCtryCcy rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaISOCtryCcy) {
			return( (CFSecJpaISOCtryCcy)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecISOCtryCcy.CLASS_CODE: {
					CFSecJpaISOCtryCcy mapped = new CFSecJpaISOCtryCcy();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecISOCtryCcy",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecISOCtryCcy");
			}
		}
	}

    @Override
    public ICFSecISOCtryCcyH newHRec() {
        ICFSecISOCtryCcyH hrec = new CFSecJpaISOCtryCcyH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaISOCtryCcyH ensureHRec(ICFSecISOCtryCcyH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaISOCtryCcyH) {
			return( (CFSecJpaISOCtryCcyH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecISOCtryCcy.CLASS_CODE: {
					CFSecJpaISOCtryCcyH mapped = new CFSecJpaISOCtryCcyH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecISOCtryCcy",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecISOCtryCcy");
			}
		}
	}
}
