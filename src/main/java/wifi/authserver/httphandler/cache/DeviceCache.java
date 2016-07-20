/**
 * @author  weigao<weiga@iflytek.com>
 *
 * @version 1.0.0
 */
package wifi.authserver.httphandler.cache;

import java.util.List;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

import wifi.authserver.comm.LogHelper;
import wifi.authserver.dao.SessionFactory;
import wifi.authserver.dao.map.DeviceMapper;

public class DeviceCache {
	
	private static DeviceCache instance = new DeviceCache();
	public static DeviceCache getInstance(){
		return instance;
	}
	
	
	private DeviceCache(){
		
	}
	
	private String queryByMacFromDB(String mac){
		SqlSession session = null;
		try{
			SqlSessionFactory factory = SessionFactory.getInstance();
			session = factory.openSession();
			DeviceMapper deviceMapper = session.getMapper(DeviceMapper.class);
			List<String> list = deviceMapper.selectByMac(mac);
			if(list!=null && list.size()!=0){
				return list.get(0);
			}
			
		}catch(Exception e){
			LogHelper.error(ExceptionUtils.getFullStackTrace(e));
		}finally{
			if(session!=null){
				session.close();
			}
		}
		return null;
	}
	
	private String queryByGwIdFromDB(String gwId){
		SqlSession session = null;
		try{
			SqlSessionFactory factory = SessionFactory.getInstance();
			session = factory.openSession();
			DeviceMapper deviceMapper = session.getMapper(DeviceMapper.class);
			List<String> list = deviceMapper.selectByGwId(gwId);
			if(list!=null && list.size()!=0){
				return list.get(0);
			}
			
		}catch(Exception e){
			LogHelper.error(ExceptionUtils.getFullStackTrace(e));
		}finally{
			if(session!=null){
				session.close();
			}
		}
		return null;
	}
	
	public String isDeviceInDao(String gwId) {
		return queryByGwIdFromDB(gwId);
	}
	
	public String getKey(String mac){
//		String key = cache.get(mac);
//		if(key==null && !query.contains(mac)){
		String	key =  queryByMacFromDB(mac);
//			cache.put(mac, key);
//			query.add(mac);
//		}
		
		return key;
	}
}
